# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded runs. Database leases make admission and cancellation worker-independent."""
import asyncio
import json
from datetime import timedelta
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import delete, func, select, update

from app.core import audit
from app.core.assistant import policy, tools
from app.core.assistant.provider import ProviderError
from app.models.models import AssistantConversation, AssistantRun, Operator


async def record(db, operator, conversation, run_id, tool, outcome, target=None):
    await audit.record(db, action="assistant.activity", actor=operator.id,
        actor_user_id=operator.id, organization_id=conversation.client_id,
        agent_id=target, detail={"conversation_id": conversation.id, "run_id": run_id,
            "tool": tool, "outcome": outcome})


async def prune(db, at=None):
    at = at or policy.now()
    expired = select(AssistantConversation.id).where(AssistantConversation.expires_at <= at)
    # Explicit child deletion also works on SQLite connections without FK enforcement.
    # Keep a body's last 24h of admission metadata after expiry so history
    # cleanup cannot reset the operator's rolling usage quota. No text survives.
    await db.execute(update(AssistantRun).where(AssistantRun.conversation_id.in_(expired)).values(body=b""))
    await db.execute(delete(AssistantRun).where(AssistantRun.conversation_id.in_(expired),
        AssistantRun.created_at <= at - timedelta(days=1)))
    result = await db.execute(delete(AssistantConversation).where(AssistantConversation.id.in_(expired),
        ~AssistantConversation.id.in_(select(AssistantRun.conversation_id))))
    return result.rowcount or 0


async def create_conversation(db, authorization, client_id):
    operator, _ = await policy.authorize(db, authorization, client_id=client_id)
    # Short per-operator lock serializes admission across all worker processes.
    await db.execute(select(Operator.id).where(Operator.id == operator.id).with_for_update())
    await prune(db)
    count = await db.scalar(select(func.count()).select_from(AssistantConversation).where(
        AssistantConversation.operator_id == operator.id, AssistantConversation.expires_at > policy.now()))
    if count >= 20:
        raise HTTPException(429, detail={"code": "assistant_conversation_limit"})
    row = AssistantConversation(id=str(uuid4()), operator_id=operator.id, client_id=client_id,
        created_at=policy.now(), expires_at=policy.now() + timedelta(days=policy.RETENTION_DAYS))
    db.add(row)
    await db.flush()
    await record(db, operator, row, None, "conversation", "created")
    await db.commit()
    return row


async def reserve(db, authorization, conversation_id, body):
    operator, conversation = await policy.authorize(db, authorization, conversation_id)
    await db.execute(select(Operator.id).where(Operator.id == operator.id).with_for_update())
    old = await db.scalar(select(AssistantRun).where(AssistantRun.conversation_id == conversation_id,
                                                    AssistantRun.request_id == str(body.request_id)))
    if old:
        return old.id, False
    owned = select(AssistantConversation.id).where(AssistantConversation.operator_id == operator.id)
    active = await db.scalar(select(AssistantRun.id).where(AssistantRun.conversation_id.in_(owned),
                AssistantRun.status == "running", AssistantRun.deadline > policy.now()).limit(1))
    if active:
        raise HTTPException(409, detail={"code": "assistant_busy"})
    daily = await db.scalar(select(func.count()).select_from(AssistantRun).where(
        AssistantRun.conversation_id.in_(owned), AssistantRun.created_at > policy.now() - timedelta(days=1)))
    count = await db.scalar(select(func.count()).select_from(AssistantRun).where(AssistantRun.conversation_id == conversation_id))
    if daily >= 100 or count >= 20:
        raise HTTPException(429, detail={"code": "assistant_run_limit"})
    row = AssistantRun(id=str(uuid4()), conversation_id=conversation_id,
        request_id=str(body.request_id), status="running", created_at=policy.now(),
        deadline=policy.now() + timedelta(seconds=policy.MAX_SECONDS), tool_count=0, usage_tokens=0)
    row.body = policy.seal(row, conversation, {"question": policy.clean_text(body.message), "answer": "", "evidence": []})
    db.add(row)
    await db.flush()
    await record(db, operator, conversation, row.id, "run", "started")
    await db.commit()
    return row.id, True


async def checked(db, authorization, conversation_id, run_id, evidence):
    operator, conversation = await policy.authorize(db, authorization, conversation_id)
    row = await db.get(AssistantRun, run_id)
    if row is None or row.conversation_id != conversation_id:
        raise HTTPException(404, "Run not found")
    if row.status != "running":
        raise ProviderError("cancelled")
    if policy.utc(row.deadline) <= policy.now():
        raise ProviderError("timeout")
    await policy.check_targets(db, operator, conversation.client_id,
        [source["endpoint_id"] for item in evidence for source in item.get("sources", [])])
    return operator, conversation, row


async def present(db, operator, conversation, row):
    body = policy.unseal(row, conversation)
    # Device movement/revocation also invalidates historical evidence and prose.
    try:
        await policy.check_targets(db, operator, conversation.client_id,
            body.get("access_endpoint_ids", []) + [source["endpoint_id"] for item in body["evidence"] for source in item.get("sources", [])])
    except HTTPException:
        body = {"question": "History restricted", "answer": "Referenced endpoints are no longer accessible in this client.", "evidence": []}
    status = row.status
    if status == "running" and policy.utc(row.deadline) <= policy.now():
        status = "failed"
        body["answer"] = "The investigation timed out or was interrupted. Retry to start a new run."
    return {"id": row.id, "request_id": row.request_id, "status": status,
            "created_at": row.created_at, "tool_count": row.tool_count, "usage_tokens": row.usage_tokens, **body}


async def history(db, authorization, conversation_id):
    operator, conversation = await policy.authorize(db, authorization, conversation_id)
    rows = (await db.execute(select(AssistantRun).where(AssistantRun.conversation_id == conversation_id)
            .order_by(AssistantRun.created_at, AssistantRun.id).limit(20))).scalars().all()
    return {"id": conversation.id, "client_id": conversation.client_id, "expires_at": conversation.expires_at,
            "runs": [await present(db, operator, conversation, row) for row in rows]}


async def cancel(db, authorization, conversation_id, request_id):
    operator, conversation = await policy.authorize(db, authorization, conversation_id)
    row = await db.scalar(select(AssistantRun).where(AssistantRun.conversation_id == conversation_id,
                                                    AssistantRun.request_id == request_id))
    if row is None:
        raise HTTPException(404, "Run not found")
    result = await db.execute(update(AssistantRun).where(AssistantRun.id == row.id, AssistantRun.status == "running")
                             .values(status="cancelled"))
    if result.rowcount:
        await record(db, operator, conversation, row.id, "run", "cancelled")
    await db.commit()
    return {"status": "cancelled" if result.rowcount else row.status}


async def run(db, authorization, conversation_id, run_id, provider):
    evidence, calls, usage = [], 0, 0
    prior_evidence = []
    access_ids = set()
    answer, outcome = "", "failed"
    try:
        async with asyncio.timeout(policy.MAX_SECONDS):
            operator, conversation, row = await checked(db, authorization, conversation_id, run_id, evidence)
            payload = policy.unseal(row, conversation)
            prior = await history(db, authorization, conversation_id)
            inputs = []
            for old in prior["runs"][-7:]:
                if old["id"] != run_id and old["status"] == "completed" and old["question"] != "History restricted":
                    targets = set(old.get("access_endpoint_ids", [])) | {source["endpoint_id"] for item in old["evidence"] for source in item.get("sources", [])}
                    if len(access_ids | targets) > 150:
                        continue  # bound inherited dependencies as well as prompt text
                    access_ids.update(targets)
                    prior_evidence.append({"sources": [{"endpoint_id": target} for target in targets]})
                    # Historical bodies are reauthorized; omit their bulky evidence.
                    inputs.extend([{"role": "user", "content": old["question"]},
                                   {"role": "assistant", "content": old["answer"][:2000]}])
            inputs.append({"role": "user", "content": payload["question"]})
            for _ in range(policy.MAX_TOOLS + 1):
                await checked(db, authorization, conversation_id, run_id, evidence + prior_evidence)
                await db.commit()  # never hold a transaction or audit lock across network I/O
                if len(policy.encoded(inputs).encode()) > policy.MAX_INPUT_BYTES:
                    raise ProviderError("input_limit")
                response = await provider.respond(inputs, tools.definitions())
                operator, conversation, row = await checked(db, authorization, conversation_id, run_id, evidence + prior_evidence)
                if len(policy.encoded(response).encode()) > policy.MAX_RESPONSE_BYTES:
                    raise ProviderError("response_limit")
                used = response.get("usage", {}).get("total_tokens")
                if not isinstance(used, int) or isinstance(used, bool) or used < 0:
                    raise ProviderError("invalid_response")
                usage += used
                if usage > policy.MAX_USAGE:
                    raise ProviderError("usage_limit")
                output = response.get("output")
                if not isinstance(output, list) or len(output) > 16:
                    raise ProviderError("invalid_response")
                functions = [item for item in output if item.get("type") == "function_call"]
                if not functions:
                    chunks = [part.get("text", "") for item in output if item.get("type") == "message"
                              for part in item.get("content", []) if part.get("type") == "output_text"]
                    answer = policy.clean_text("\n".join(chunks), 8000)
                    if not answer or not evidence:
                        raise ProviderError("no_evidence")
                    if any(item["outcome"] != "observed" for item in evidence):
                        answer = "Some requested data is missing, partial, or could not be retrieved. Review the limitations and available observations below; this run cannot establish a complete answer."
                    outcome = "completed"
                    break
                if calls + len(functions) > policy.MAX_TOOLS:
                    raise ProviderError("tool_limit")
                inputs.extend(output)
                for item in functions:
                    name = item.get("name")
                    calls += 1
                    try:
                        args = tools.parse(name, item.get("arguments"))
                    except ValueError:
                        await record(db, operator, conversation, run_id, "rejected", "invalid_tool")
                        await db.commit()
                        raise ProviderError("invalid_tool") from None
                    operator, conversation, row = await checked(db, authorization, conversation_id, run_id, evidence + prior_evidence)
                    target = str(args.endpoint_id) if getattr(args, "endpoint_id", None) else None
                    try:
                        result = await tools.execute(name, args, db, operator, conversation)
                    except HTTPException:
                        await record(db, operator, conversation, run_id, name, "denied")
                        await db.commit()
                        raise  # authorization failures abort, never become evidence
                    except Exception:
                        result = {"tool": name, "outcome": "unavailable", "sources": [],
                                  "data": {"note": "Tool failed; no observation was established."}}
                    evidence.append(json.loads(policy.encoded(result)))
                    await record(db, operator, conversation, run_id, name, result["outcome"], target)
                    await db.commit()
                    inputs.append({"type": "function_call_output", "call_id": item["call_id"],
                                   "output": policy.encoded(result)})
            else:
                raise ProviderError("tool_limit")
    except HTTPException:
        await db.rollback()
        await finish(db, conversation_id, run_id, "failed", "Access changed; no answer is available.", [], calls, usage)
        raise
    except (TimeoutError, ProviderError):
        await db.rollback()
        answer = "The investigation could not be completed within its limits or the provider is unavailable. No complete answer was established. Retry if needed."
    except asyncio.CancelledError:
        await db.rollback()
        await finish(db, conversation_id, run_id, "cancelled", "Investigation cancelled.", [], calls, usage)
        raise
    except Exception:
        await db.rollback()
        answer = "The investigation failed. No complete answer was established. Retry if needed."
    # Final authorization includes every target after the last provider wait.
    try:
        await checked(db, authorization, conversation_id, run_id, evidence + prior_evidence)
    except ProviderError:
        # A cancelled run cannot publish or overwrite its terminal state.
        outcome, answer, evidence = "failed", "Investigation cancelled or timed out.", []
    except HTTPException:
        await db.rollback()
        await finish(db, conversation_id, run_id, "failed", "Access changed; no answer is available.", [], calls, usage)
        raise
    await finish(db, conversation_id, run_id, outcome, answer, evidence, calls, usage, access_ids)


async def finish(db, conversation_id, run_id, status, answer, evidence, calls, usage, inherited_ids=()):
    # Internal metadata finalization does not read endpoint data or expose results.
    db.expire_all()
    row = await db.get(AssistantRun, run_id)
    conversation = await db.get(AssistantConversation, conversation_id)
    if row is None or conversation is None:
        return
    body = policy.unseal(row, conversation)
    targets = set(inherited_ids) | {source["endpoint_id"] for item in evidence for source in item.get("sources", [])}
    body.update(answer=answer, evidence=evidence, access_endpoint_ids=sorted(targets))
    result = await db.execute(update(AssistantRun).where(AssistantRun.id == run_id, AssistantRun.status == "running")
        .values(status=status, body=policy.seal(row, conversation, body), tool_count=calls, usage_tokens=usage))
    if result.rowcount:
        operator = await db.get(Operator, conversation.operator_id)
        if operator:
            await record(db, operator, conversation, run_id, "run", status)
    await db.commit()
