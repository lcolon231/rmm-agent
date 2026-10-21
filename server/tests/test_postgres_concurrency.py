# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL-only concurrency tests (issue #286).

SQLite serializes writers and ignores ``FOR UPDATE``, so the same tests on
SQLite pass whether or not the row locks and constraints exist. Each test here
drives the real API against a throwaway PostgreSQL database with two requests
in flight at once. A barrier (``wait_for_lock_waiters``) makes sure both
requests have passed their application checks before either one commits, so
the race happens on every run.
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_postgres_concurrency.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
_LOGIN = os.environ.setdefault("NODELINK_TEST_LOGIN", "op-pass")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import func, select, text  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker  # noqa: E402

from app.core import audit  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V3  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.database import get_db  # noqa: E402
from app.core.security import hash_password, hash_token  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    ApprovalDecision,
    ApprovalRequest,
    ApprovalRequestStatus,
    AuditEvent,
    Client,
    ClientRole,
    Command,
    CommandKind,
    CommandStatus,
    Operator,
    OperatorClientMembership,
    OperatorRole,
    ScriptExecutionScope,
    Site,
    SupportConversation,
    SupportConversationStatus,
    SupportParty,
)
from tests.conftest import wait_for_lock_waiters  # noqa: E402

pytestmark = pytest.mark.postgres

REQUESTER = "req@nodelink.test"
APPROVER_ONE = "appr1@nodelink.test"
APPROVER_TWO = "appr2@nodelink.test"
SCRIPT_PAYLOAD = {"script": "Restart-Service -Name Spooler"}


@pytest_asyncio.fixture
async def pg(pg_engine):
    """(API client, sessionmaker) with the app's ``get_db`` bound to PostgreSQL."""
    maker = async_sessionmaker(pg_engine, expire_on_commit=False, autoflush=False)

    async def pg_db():
        async with maker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async with maker() as db:
        db.add_all(
            [
                Operator(
                    email=email,
                    password_hash=hash_password(_LOGIN),
                    role=role,
                    script_execution_scope=ScriptExecutionScope.global_,
                )
                for email, role in (
                    (REQUESTER, OperatorRole.operator),
                    (APPROVER_ONE, OperatorRole.operator),
                    (APPROVER_TWO, OperatorRole.admin),
                )
            ]
        )
        await db.commit()

    app.dependency_overrides[get_db] = pg_db
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test/api/v1"
        ) as client:
            yield client, maker
    finally:
        app.dependency_overrides.pop(get_db, None)


async def login(client, email: str) -> dict:
    response = await client.post(
        "/auth/login", json={"email": email, "password": _LOGIN}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def seed_agent(maker, token: str, **fields) -> str:
    async with maker() as db:
        tenant = Client(name=f"Race tenant {uuid4().hex}")
        db.add(tenant)
        await db.flush()
        site = Site(client_id=tenant.id, name="HQ")
        db.add(site)
        await db.flush()
        agent = Agent(
            site_id=site.id, hostname="RACE-PC", token_hash=hash_token(token), **fields
        )
        db.add(agent)
        await db.commit()
        return agent.id


async def hold_row(maker, model, row_id: str):
    """Open a transaction holding ``FOR UPDATE`` on one row; caller releases."""
    holder = maker()
    await holder.execute(select(model).where(model.id == row_id).with_for_update())
    return holder


async def hold_audit_lock(maker):
    """Open a transaction holding the audit-append advisory lock.

    Every audited write takes this lock, so holding it parks a request right
    after its own row writes and before its commit, without blocking anything
    the request does earlier.
    """
    holder = maker()
    await holder.execute(
        text("SELECT pg_advisory_xact_lock(:key)"), {"key": audit._APPEND_LOCK_KEY}
    )
    return holder


async def race(maker, holder, *requests, waiters: int | None = None):
    """Start ``requests``, wait until they are all blocked, then release."""
    tasks = [asyncio.create_task(request) for request in requests]
    try:
        await wait_for_lock_waiters(
            maker.kw["bind"], len(tasks) if waiters is None else waiters
        )
    finally:
        await holder.rollback()
        await holder.close()
    return await asyncio.gather(*tasks)


async def audit_count(maker, action: str) -> int:
    async with maker() as db:
        return await db.scalar(
            select(func.count()).select_from(AuditEvent).where(AuditEvent.action == action)
        )


# --------------------------------------------------------------------------- #
# Two-person authorization (issue #64)
# --------------------------------------------------------------------------- #
async def provision_approval(client, maker, *, required_approvals: int = 2):
    """A tenant with one agent and a pending approval request for it."""
    admin = await login(client, APPROVER_TWO)
    org = (
        await client.post(
            "/clients", json={"name": f"Approvals {uuid4().hex}"}, headers=admin
        )
    ).json()
    site = (
        await client.post(
            "/sites", json={"client_id": org["id"], "name": "HQ"}, headers=admin
        )
    ).json()
    token = (
        await client.post(
            "/enrollment-tokens", json={"site_id": site["id"]}, headers=admin
        )
    ).json()["token"]
    agent_id = (
        await client.post(
            "/enroll",
            json={
                "enrollment_token": token,
                "hostname": "APPROVE-PC",
                "os": "windows",
                "supported_command_envelope_versions": [COMMAND_ENVELOPE_V3],
                "supported_capabilities": [],
            },
        )
    ).json()["agent_id"]
    async with maker() as db:
        for email in (REQUESTER, APPROVER_ONE):
            operator_id = await db.scalar(
                select(Operator.id).where(Operator.email == email)
            )
            db.add(
                OperatorClientMembership(
                    operator_id=operator_id,
                    client_id=org["id"],
                    role=ClientRole.client_operator,
                    granted_by="test-seed",
                    reason="test",
                )
            )
        await db.commit()

    policy = await client.post(
        "/approval-policies",
        json={
            "name": f"Dual control {uuid4().hex[:8]}",
            "scope": "client",
            "scope_id": org["id"],
            "command_kinds": ["powershell"],
            "required_approvals": required_approvals,
            "request_ttl_seconds": 3600,
        },
        headers=admin,
    )
    assert policy.status_code == 201, policy.text
    created = await client.post(
        "/approval-requests",
        json={
            "agent_id": agent_id,
            "kind": "powershell",
            "payload": SCRIPT_PAYLOAD,
            "reason": "Spooler is wedged on the print server, INC-4711",
        },
        headers=await login(client, REQUESTER),
    )
    assert created.status_code == 201, created.text
    return agent_id, created.json()["id"]


def approve(client, request_id: str, headers: dict):
    return client.post(
        f"/approval-requests/{request_id}/approve",
        json={"reason": "Reviewed the change window for INC-4711"},
        headers=headers,
    )


def dispatch(client, agent_id: str, request_id: str, headers: dict):
    return client.post(
        f"/agents/{agent_id}/commands",
        json={
            "kind": "powershell",
            "payload": SCRIPT_PAYLOAD,
            "approval_request_id": request_id,
        },
        headers=headers,
    )


async def test_one_operator_concurrent_approvals_count_once(pg):
    """``ux_approval_decision_one_per_operator`` turns the loser into a 409.

    Both requests pass the application's "already decided?" check because
    neither sees the other's uncommitted decision; only the unique constraint
    can refuse the second.
    """
    client, maker = pg
    _, request_id = await provision_approval(client, maker)
    headers = await login(client, APPROVER_ONE)

    holder = await hold_audit_lock(maker)
    responses = await race(
        maker, holder, approve(client, request_id, headers), approve(client, request_id, headers)
    )

    assert sorted(r.status_code for r in responses) == [200, 409]
    loser = next(r for r in responses if r.status_code == 409)
    assert loser.json()["detail"]["code"] == "approval_already_recorded"
    async with maker() as db:
        decisions = (
            await db.scalars(
                select(ApprovalDecision).where(ApprovalDecision.request_id == request_id)
            )
        ).all()
        approval = await db.get(ApprovalRequest, request_id)
    assert len(decisions) == 1
    assert approval.status == ApprovalRequestStatus.pending


async def test_distinct_concurrent_approvals_reach_the_threshold(pg):
    """Two different approvers deciding at once must still approve the request.

    Each request counts the decisions it can see plus its own. Unless the
    request row serializes them, both count one of two and the request stays
    pending forever with two recorded approvals.
    """
    client, maker = pg
    _, request_id = await provision_approval(client, maker)
    first = await login(client, APPROVER_ONE)
    second = await login(client, APPROVER_TWO)

    holder = await hold_audit_lock(maker)
    responses = await race(
        maker, holder, approve(client, request_id, first), approve(client, request_id, second)
    )

    assert [r.status_code for r in responses] == [200, 200], [r.text for r in responses]
    async with maker() as db:
        approval = await db.get(ApprovalRequest, request_id)
        decisions = await db.scalar(
            select(func.count())
            .select_from(ApprovalDecision)
            .where(ApprovalDecision.request_id == request_id)
        )
    assert decisions == 2
    assert approval.status == ApprovalRequestStatus.approved


async def test_concurrent_dispatch_spends_one_approval_once(pg):
    """The conditional ``approved -> consumed`` UPDATE admits exactly one dispatch."""
    client, maker = pg
    agent_id, request_id = await provision_approval(client, maker)
    assert (await approve(client, request_id, await login(client, APPROVER_ONE))).status_code == 200
    assert (await approve(client, request_id, await login(client, APPROVER_TWO))).status_code == 200
    headers = await login(client, REQUESTER)

    # Both dispatches validate the approval as "approved", then park on the
    # held row at the spend UPDATE (or on the audit lock the winner holds).
    holder = await hold_row(maker, ApprovalRequest, request_id)
    responses = await race(
        maker,
        holder,
        dispatch(client, agent_id, request_id, headers),
        dispatch(client, agent_id, request_id, headers),
    )

    assert sorted(r.status_code for r in responses) == [200, 409], [r.text for r in responses]
    loser = next(r for r in responses if r.status_code == 409)
    assert loser.json()["detail"]["code"] == "approval_request_already_consumed"
    async with maker() as db:
        commands = await db.scalar(select(func.count()).select_from(Command))
        approval = await db.get(ApprovalRequest, request_id)
    assert commands == 1
    assert approval.status == ApprovalRequestStatus.consumed


# --------------------------------------------------------------------------- #
# Row locks
# --------------------------------------------------------------------------- #
async def test_concurrent_reattach_serializes_on_the_agent_row(pg):
    """Two reattaches of one expired credential must not lose an update.

    Without the agent row lock both requests read the same generation and the
    later commit silently discards the earlier rotation's bookkeeping.
    """
    client, maker = pg
    expired = "expired-agent-token"
    now = datetime.now(timezone.utc)
    agent_id = await seed_agent(
        maker,
        expired,
        credential_expires_at=now - timedelta(minutes=5),
        credential_generation=1,
    )
    bearer = {"Authorization": f"Bearer {expired}"}

    def reattach():
        return client.post(
            "/agents/credentials/reattach",
            json={"rotation_nonce": f"nonce-{uuid4().hex}"},
            headers=bearer,
        )

    holder = await hold_row(maker, Agent, agent_id)
    responses = await race(maker, holder, reattach(), reattach())

    assert [r.status_code for r in responses] == [200, 200], [r.text for r in responses]
    issued = {r.json()["credential_generation"]: r.json()["agent_token"] for r in responses}
    assert sorted(issued) == [2, 3]
    async with maker() as db:
        agent = await db.get(Agent, agent_id)
    assert agent.credential_generation == 3
    # The later rotation's bearer is current; the original stays in the
    # overlap slot so a lost response can still be retried.
    assert agent.token_hash == hash_token(issued[3])
    assert agent.previous_token_hash == hash_token(expired)
    assert await audit_count(maker, "agent.credential_reattached") == 2


async def test_conflicting_concurrent_results_accept_exactly_one(pg):
    """Two different results for one command: one 204, one 409, one audit row."""
    client, maker = pg
    token = "result-agent-token"
    agent_id = await seed_agent(maker, token)
    async with maker() as db:
        command = Command(
            agent_id=agent_id,
            kind=CommandKind.powershell,
            payload=SCRIPT_PAYLOAD,
            envelope_version=COMMAND_ENVELOPE_V3,
            status=CommandStatus.dispatched,
        )
        db.add(command)
        await db.commit()
        command_id = command.id
    bearer = {"Authorization": f"Bearer {token}"}

    def submit(exit_code: int):
        return client.post(
            f"/commands/{command_id}/result",
            json={"exit_code": exit_code, "stdout": f"exit {exit_code}"},
            headers=bearer,
        )

    holder = await hold_row(maker, Command, command_id)
    responses = await race(maker, holder, submit(0), submit(1))

    assert sorted(r.status_code for r in responses) == [204, 409], [r.text for r in responses]
    winner = 0 if responses[0].status_code == 204 else 1
    loser = responses[1 - winner]
    assert loser.json()["detail"]["code"] == "command_result_conflict"
    async with maker() as db:
        stored = await db.get(Command, command_id)
    assert stored.exit_code == winner
    assert stored.stdout == f"exit {winner}"
    assert await audit_count(maker, "command.completed") == 1


async def test_heartbeat_racing_a_close_never_revives_the_launch_token(pg, monkeypatch):
    """The technician-launch row lock (a94747f0) under a real concurrent close.

    The launch token has lapsed, so the heartbeat would re-mint it. The close
    commits while the heartbeat is blocked; the heartbeat must then see the
    conversation as closed instead of writing a fresh token onto it.
    """
    monkeypatch.setattr(settings, "support_chat_base_url", "https://support.example.test")
    client, maker = pg
    token = "chat-agent-token"
    agent_id = await seed_agent(
        maker, token, supported_capabilities=["support-chat-v1", "support-chat-launch-v1"]
    )
    async with maker() as db:
        client_id = await db.scalar(
            select(Site.client_id).join(Agent, Agent.site_id == Site.id).where(Agent.id == agent_id)
        )
        conversation = SupportConversation(
            agent_id=agent_id,
            client_id=client_id,
            opened_by=SupportParty.technician,
            token_hash=hash_token("lapsed-launch-token"),
            token_expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
        db.add(conversation)
        await db.commit()
        conversation_id = conversation.id

    # The holder plays the operator's close: it locks the row first and writes
    # what support_chat.close() writes. It deliberately skips the audit append
    # so it never contends with the heartbeat for the audit advisory lock.
    holder = await hold_row(maker, SupportConversation, conversation_id)
    closing = await holder.get(SupportConversation, conversation_id)
    closing.status = SupportConversationStatus.closed
    closing.closed_at = datetime.now(timezone.utc)
    closing.token_hash = ""
    await holder.flush()

    heartbeat = asyncio.create_task(
        client.post("/heartbeat", json={}, headers={"Authorization": f"Bearer {token}"})
    )
    try:
        await wait_for_lock_waiters(maker.kw["bind"], 1)
    finally:
        await holder.commit()
        await holder.close()
    response = await heartbeat

    assert response.status_code == 200, response.text
    assert response.json()["chat_launch_requested"] is None
    async with maker() as db:
        stored = await db.get(SupportConversation, conversation_id)
    assert stored.status == SupportConversationStatus.closed
    assert stored.token_hash == ""
