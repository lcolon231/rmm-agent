# SPDX-License-Identifier: AGPL-3.0-only
"""Approval workflow and two-person authorization tests (issue #64).

Covers the properties the control is supposed to hold, each as its own test:
self-approval refusal, distinct approvers, duplicate and concurrent decisions,
expiry, command mutation between review and execution, approver role loss,
single-use consumption, tenant scope, the scheduler and interactive-shell
bypasses, and the audit evidence produced along the way.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_approvals.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
# Login values come from the environment (defaulted for local runs) so no
# password literal sits next to an operator identity.
_LOGIN = os.environ.setdefault("NODELINK_TEST_LOGIN", "op-pass")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core import audit  # noqa: E402
from app.core.approvals import binding_digest, resolve_policy  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V3  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.scheduler import dispatch_scheduled_tasks_once  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    ApprovalDecision,
    ApprovalRequest,
    ApprovalRequestStatus,
    AuditEvent,
    ClientRole,
    Command,
    CommandKind,
    Operator,
    OperatorClientMembership,
    OperatorRole,
    ScheduleConcurrencyPolicy,
    ScheduleMisfirePolicy,
    ScheduleTargetType,
    ScheduledTask,
    ScriptExecutionScope,
)

REQUESTER = "req@nodelink.test"
APPROVER_ONE = "appr1@nodelink.test"
APPROVER_TWO = "appr2@nodelink.test"
OUTSIDER = "outsider@nodelink.test"
PLATFORM = "platform@nodelink.test"

SCRIPT_PAYLOAD = {"script": "Restart-Service -Name Spooler"}


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                # Everyone who may dispatch or approve arbitrary script needs the
                # explicit global script grant; that grant is also the lever the
                # role-loss test pulls.
                Operator(
                    email=REQUESTER,
                    password_hash=hash_password(_LOGIN),
                    role=OperatorRole.operator,
                    script_execution_scope=ScriptExecutionScope.global_,
                ),
                Operator(
                    email=APPROVER_ONE,
                    password_hash=hash_password(_LOGIN),
                    role=OperatorRole.operator,
                    script_execution_scope=ScriptExecutionScope.global_,
                ),
                Operator(
                    email=APPROVER_TWO,
                    password_hash=hash_password(_LOGIN),
                    role=OperatorRole.admin,
                    script_execution_scope=ScriptExecutionScope.global_,
                ),
                Operator(
                    email=OUTSIDER,
                    password_hash=hash_password(_LOGIN),
                    role=OperatorRole.admin,
                    script_execution_scope=ScriptExecutionScope.global_,
                ),
                Operator(
                    email=PLATFORM,
                    password_hash=hash_password(_LOGIN),
                    role=OperatorRole.admin,
                    is_platform_admin=True,
                    script_execution_scope=ScriptExecutionScope.global_,
                ),
            ]
        )
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test/api/v1"
    ) as value:
        yield value
    await engine.dispose()


async def auth(client, email=REQUESTER, password=_LOGIN):
    response = await client.post(
        "/auth/login", json={"email": email, "password": password}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def operator_id(email: str) -> str:
    async with AsyncSessionLocal() as db:
        return (
            await db.execute(select(Operator.id).where(Operator.email == email))
        ).scalar_one()


async def grant_membership(email: str, client_id: str, role: ClientRole) -> None:
    async with AsyncSessionLocal() as db:
        op_id = (
            await db.execute(select(Operator.id).where(Operator.email == email))
        ).scalar_one()
        db.add(
            OperatorClientMembership(
                operator_id=op_id,
                client_id=client_id,
                role=role,
                granted_by="test-seed",
                reason="test",
            )
        )
        await db.commit()


async def provision(client, capabilities=()):
    """Create a tenant with one enrolled agent and admit the cast to it."""
    admin_headers = await auth(client, APPROVER_TWO)
    org = (
        await client.post(
            "/clients", json={"name": f"Approvals {uuid4().hex}"}, headers=admin_headers
        )
    ).json()
    site = (
        await client.post(
            "/sites",
            json={"client_id": org["id"], "name": "HQ"},
            headers=admin_headers,
        )
    ).json()
    token = (
        await client.post(
            "/enrollment-tokens", json={"site_id": site["id"]}, headers=admin_headers
        )
    ).json()["token"]
    enrollment = (
        await client.post(
            "/enroll",
            json={
                "enrollment_token": token,
                "hostname": "APPROVE-PC",
                "os": "windows",
                "supported_command_envelope_versions": [COMMAND_ENVELOPE_V3],
                "supported_capabilities": list(capabilities),
            },
        )
    ).json()
    await grant_membership(REQUESTER, org["id"], ClientRole.client_operator)
    await grant_membership(APPROVER_ONE, org["id"], ClientRole.client_operator)
    return org["id"], site["id"], enrollment["agent_id"]


async def create_policy(
    client,
    client_id: str,
    *,
    kinds=("powershell",),
    required_approvals: int = 2,
    ttl_seconds: int = 3600,
    actor: str = APPROVER_TWO,
):
    headers = await auth(client, actor)
    response = await client.post(
        "/approval-policies",
        json={
            "name": f"Dual control {uuid4().hex[:8]}",
            "scope": "client",
            "scope_id": client_id,
            "command_kinds": list(kinds),
            "required_approvals": required_approvals,
            "request_ttl_seconds": ttl_seconds,
        },
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()


async def raise_request(client, agent_id: str, payload=None, actor: str = REQUESTER):
    headers = await auth(client, actor)
    response = await client.post(
        "/approval-requests",
        json={
            "agent_id": agent_id,
            "kind": "powershell",
            "payload": SCRIPT_PAYLOAD if payload is None else payload,
            "reason": "Spooler is wedged on the print server, INC-4711",
        },
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()


async def decide(client, request_id: str, actor: str, verdict: str = "approve"):
    headers = await auth(client, actor)
    return await client.post(
        f"/approval-requests/{request_id}/{verdict}",
        json={"reason": f"Reviewed the change window for INC-4711 ({verdict})"},
        headers=headers,
    )


async def dispatch(
    client, agent_id: str, approval_request_id=None, payload=None, actor=REQUESTER
):
    headers = await auth(client, actor)
    body = {
        "kind": "powershell",
        "payload": SCRIPT_PAYLOAD if payload is None else payload,
    }
    if approval_request_id is not None:
        body["approval_request_id"] = approval_request_id
    return await client.post(
        f"/agents/{agent_id}/commands", json=body, headers=headers
    )


async def audit_actions() -> list[str]:
    async with AsyncSessionLocal() as db:
        return [
            row[0]
            for row in (
                await db.execute(select(AuditEvent.action).order_by(AuditEvent.seq))
            ).all()
        ]


async def audit_details(action: str) -> list[dict]:
    async with AsyncSessionLocal() as db:
        return [
            row[0]
            for row in (
                await db.execute(
                    select(AuditEvent.detail)
                    .where(AuditEvent.action == action)
                    .order_by(AuditEvent.seq)
                )
            ).all()
        ]


# --------------------------------------------------------------------------- #
# Policy configuration
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_no_policy_leaves_dispatch_unchanged(client):
    """The capability is inert until an administrator writes a policy."""
    _, _, agent_id = await provision(client)
    response = await dispatch(client, agent_id)
    assert response.status_code == 200, response.text
    async with AsyncSessionLocal() as db:
        command = (await db.execute(select(Command))).scalar_one()
    assert command.approval_request_id is None
    assert "approval_gate.denied" not in await audit_actions()


@pytest.mark.asyncio
async def test_global_policy_requires_platform_admin(client):
    """A policy that governs every tenant may only be written across tenants."""
    await provision(client)
    tenant_admin = await auth(client, APPROVER_TWO)
    body = {
        "name": "Fleet wide",
        "scope": "global",
        "scope_id": None,
        "command_kinds": ["powershell"],
    }
    refused = await client.post("/approval-policies", json=body, headers=tenant_admin)
    assert refused.status_code == 403
    assert (
        refused.json()["detail"]["code"]
        == "approval_policy_global_requires_platform_admin"
    )

    platform = await auth(client, PLATFORM)
    allowed = await client.post("/approval-policies", json=body, headers=platform)
    assert allowed.status_code == 201, allowed.text


@pytest.mark.asyncio
async def test_policy_write_requires_admin_role(client):
    """An ordinary operator cannot put commands behind approval, or take them out."""
    client_id, _, _ = await provision(client)
    headers = await auth(client, REQUESTER)
    response = await client.post(
        "/approval-policies",
        json={
            "name": "Sneaky",
            "scope": "client",
            "scope_id": client_id,
            "command_kinds": ["powershell"],
        },
        headers=headers,
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_policy_edit_does_not_change_requests_in_flight(client):
    """A request keeps the terms it was raised under."""
    client_id, _, agent_id = await provision(client)
    policy = await create_policy(client, client_id, required_approvals=2)
    approval = await raise_request(client, agent_id)
    assert approval["required_approvals"] == 2

    admin = await auth(client, APPROVER_TWO)
    edited = await client.patch(
        f"/approval-policies/{policy['id']}",
        json={"required_approvals": 1},
        headers=admin,
    )
    assert edited.status_code == 200, edited.text

    # One approval must still not be enough for the in-flight request.
    assert (await decide(client, approval["id"], APPROVER_ONE)).status_code == 200
    detail = (
        await client.get(
            f"/approval-requests/{approval['id']}", headers=await auth(client)
        )
    ).json()
    assert detail["status"] == "pending"
    assert detail["required_approvals"] == 2




@pytest.mark.asyncio
async def test_most_specific_policy_wins_and_a_narrow_one_cannot_drop_a_broader(client):
    """Scopes are evaluated independently; the most specific *match* governs."""
    client_id, site_id, agent_id = await provision(client)
    platform = await auth(client, PLATFORM)

    # Global: two approvals for powershell. Site: one approval, and it does not
    # mention `shell` at all.
    await client.post(
        "/approval-policies",
        json={
            "name": "Global scripts",
            "scope": "global",
            "scope_id": None,
            "command_kinds": ["powershell", "shell"],
            "required_approvals": 2,
        },
        headers=platform,
    )
    await client.post(
        "/approval-policies",
        json={
            "name": "Site scripts",
            "scope": "site",
            "scope_id": site_id,
            "command_kinds": ["powershell"],
            "required_approvals": 1,
        },
        headers=platform,
    )

    async with AsyncSessionLocal() as db:
        agent = await db.get(Agent, agent_id)
        powershell = await resolve_policy(db, agent, CommandKind.powershell)
        shell = await resolve_policy(db, agent, CommandKind.shell)
        inventory = await resolve_policy(db, agent, CommandKind.collect_inventory)

    # The site policy is more specific for the kind it names.
    assert powershell is not None and powershell.name == "Site scripts"
    assert powershell.required_approvals == 1
    # The site policy omitting `shell` does not suppress the global one.
    assert shell is not None and shell.name == "Global scripts"
    # A kind no policy names is ungoverned.
    assert inventory is None

    # And the resolved policy is the one actually enforced: one approval is
    # enough here even though the global policy asks for two.
    approval = await raise_request(client, agent_id)
    assert approval["required_approvals"] == 1
    assert (await decide(client, approval["id"], APPROVER_ONE)).status_code == 200
    assert (await dispatch(client, agent_id, approval["id"])).status_code == 200


@pytest.mark.asyncio
async def test_request_ttl_is_clamped_to_the_ceiling(client):
    """A policy may ask for less than the ceiling; never for more."""
    client_id, _, agent_id = await provision(client)
    admin = await auth(client, APPROVER_TWO)

    too_long = await client.post(
        "/approval-policies",
        json={
            "name": "Forever",
            "scope": "client",
            "scope_id": client_id,
            "command_kinds": ["powershell"],
            "request_ttl_seconds": 30 * 24 * 3600,
        },
        headers=admin,
    )
    assert too_long.status_code == 422

    await create_policy(client, client_id, ttl_seconds=900)
    approval = await raise_request(client, agent_id)
    lifetime = datetime.fromisoformat(approval["expires_at"]) - datetime.fromisoformat(
        approval["created_at"]
    )
    assert lifetime <= timedelta(seconds=900)


@pytest.mark.asyncio
async def test_a_policy_may_not_be_written_for_another_tenant(client):
    """Policy administration is tenant-scoped like everything else."""
    client_id, _, _ = await provision(client)
    outsider = await auth(client, OUTSIDER)
    response = await client.post(
        "/approval-policies",
        json={
            "name": "Reach across",
            "scope": "client",
            "scope_id": client_id,
            "command_kinds": ["powershell"],
        },
        headers=outsider,
    )
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "approval_policy_scope_target_not_found"


# --------------------------------------------------------------------------- #
# The two-person path
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_dispatch_without_approval_is_refused_and_audited(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)

    response = await dispatch(client, agent_id)
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "approval_required"

    async with AsyncSessionLocal() as db:
        assert (await db.execute(select(Command))).first() is None
    denials = await audit_details("approval_gate.denied")
    assert [entry["reason"] for entry in denials] == ["approval_required"]


@pytest.mark.asyncio
async def test_two_distinct_approvals_authorize_exactly_one_dispatch(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    approval = await raise_request(client, agent_id)

    first = await decide(client, approval["id"], APPROVER_ONE)
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "pending"

    # One approval is not two: the dispatch must still fail closed.
    early = await dispatch(client, agent_id, approval["id"])
    assert early.status_code == 409
    assert early.json()["detail"]["code"] == "approval_request_not_approved"

    second = await decide(client, approval["id"], APPROVER_TWO)
    assert second.status_code == 200, second.text
    assert second.json()["status"] == "approved"
    assert second.json()["approvals_recorded"] == 2

    dispatched = await dispatch(client, agent_id, approval["id"])
    assert dispatched.status_code == 200, dispatched.text

    async with AsyncSessionLocal() as db:
        command = (await db.execute(select(Command))).scalar_one()
        stored = await db.get(ApprovalRequest, approval["id"])
        assert command.approval_request_id == approval["id"]
        assert stored.status == ApprovalRequestStatus.consumed
        assert stored.consumed_at is not None

    allowed = await audit_details("approval_gate.allowed")
    assert len(allowed) == 1
    assert allowed[0]["payload_sha256"] == approval["payload_sha256"]
    assert len(allowed[0]["approver_operator_ids"]) == 2

    # Single use: the same approval cannot authorize a second run.
    replay = await dispatch(client, agent_id, approval["id"])
    assert replay.status_code == 409
    assert replay.json()["detail"]["code"] == "approval_request_already_consumed"


@pytest.mark.asyncio
async def test_single_approval_policy_still_excludes_the_requester(client):
    """``required_approvals=1`` lowers the count, never the self-approval rule."""
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id, required_approvals=1)
    approval = await raise_request(client, agent_id)

    mine = await decide(client, approval["id"], REQUESTER)
    assert mine.status_code == 403
    assert mine.json()["detail"]["code"] == "approval_self_not_permitted"

    theirs = await decide(client, approval["id"], APPROVER_ONE)
    assert theirs.status_code == 200
    assert theirs.json()["status"] == "approved"
    assert (await dispatch(client, agent_id, approval["id"])).status_code == 200


@pytest.mark.asyncio
async def test_self_approval_is_refused_and_audited(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    approval = await raise_request(client, agent_id)

    response = await decide(client, approval["id"], REQUESTER)
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "approval_self_not_permitted"

    denials = await audit_details("approval_request.decision_denied")
    assert [entry["reason"] for entry in denials] == ["approval_self_not_permitted"]
    async with AsyncSessionLocal() as db:
        assert (await db.execute(select(ApprovalDecision))).first() is None


@pytest.mark.asyncio
async def test_one_identity_cannot_approve_twice(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    approval = await raise_request(client, agent_id)

    assert (await decide(client, approval["id"], APPROVER_ONE)).status_code == 200
    duplicate = await decide(client, approval["id"], APPROVER_ONE)
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"]["code"] == "approval_already_recorded"

    async with AsyncSessionLocal() as db:
        decisions = (await db.execute(select(ApprovalDecision))).scalars().all()
    assert len(decisions) == 1


@pytest.mark.asyncio
async def test_duplicate_decision_row_is_rejected_by_the_database(client):
    """The unique constraint, not the application check, is the real guarantee."""
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    approval = await raise_request(client, agent_id)
    assert (await decide(client, approval["id"], APPROVER_ONE)).status_code == 200

    from sqlalchemy.exc import IntegrityError

    approver = await operator_id(APPROVER_ONE)
    async with AsyncSessionLocal() as db:
        db.add(
            ApprovalDecision(
                request_id=approval["id"],
                operator_id=approver,
                operator_email=APPROVER_ONE,
                operator_role=OperatorRole.operator,
                decision="approve",
                reason="second bite",
                created_at=datetime.now(timezone.utc),
            )
        )
        with pytest.raises(IntegrityError):
            await db.commit()


@pytest.mark.asyncio
async def test_concurrent_dispatch_spends_the_approval_once(client):
    """Two dispatches racing on one approval: exactly one command is created."""
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    approval = await raise_request(client, agent_id)
    await decide(client, approval["id"], APPROVER_ONE)
    await decide(client, approval["id"], APPROVER_TWO)

    import asyncio

    first, second = await asyncio.gather(
        dispatch(client, agent_id, approval["id"]),
        dispatch(client, agent_id, approval["id"]),
        return_exceptions=True,
    )
    statuses = sorted(
        response.status_code
        for response in (first, second)
        if not isinstance(response, Exception)
    )
    assert 200 in statuses
    async with AsyncSessionLocal() as db:
        commands = (await db.execute(select(Command))).scalars().all()
    assert len(commands) == 1



@pytest.mark.asyncio
async def test_a_later_gate_refusal_does_not_burn_the_approval(client):
    """Two people's review is not spent on a command that never ran.

    Approval is validated before any payload transform but consumed only once
    every other gate has passed. Here the power-operation policy refuses for
    want of a maintenance window, after the approval gate has already allowed —
    the approval must survive, spendable, rather than being marked consumed.
    """
    client_id, _, agent_id = await provision(client, capabilities=("power-operations-v1",))
    await create_policy(
        client, client_id, kinds=("reboot",), required_approvals=1, actor=PLATFORM
    )

    reboot_payload = {
        "confirm": True,
        "reason": "Quarterly patching restart, CHG-2208",
        "delay_seconds": 300,
        "user_consent": "no_user_session",
    }
    headers = await auth(client, APPROVER_TWO)
    created = await client.post(
        "/approval-requests",
        json={
            "agent_id": agent_id,
            "kind": "reboot",
            "payload": reboot_payload,
            "reason": "Quarterly patching restart, CHG-2208",
        },
        headers=headers,
    )
    assert created.status_code == 201, created.text
    approval = created.json()

    platform = await auth(client, PLATFORM)
    approved = await client.post(
        f"/approval-requests/{approval['id']}/approve",
        json={"reason": "Change approved for the Saturday window"},
        headers=platform,
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"

    # No maintenance window covers this endpoint, so the power-operation policy
    # refuses after the approval gate has already allowed.
    refused = await client.post(
        f"/agents/{agent_id}/commands",
        json={
            "kind": "reboot",
            "payload": reboot_payload,
            "approval_request_id": approval["id"],
        },
        headers=headers,
    )
    assert refused.status_code >= 400
    async with AsyncSessionLocal() as db:
        stored = await db.get(ApprovalRequest, approval["id"])
        assert (await db.execute(select(Command))).first() is None
    assert stored.status == ApprovalRequestStatus.approved
    assert stored.consumed_at is None

# --------------------------------------------------------------------------- #
# Binding, expiry, and eligibility
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_mutated_command_cannot_reuse_an_approval(client):
    """The approval is bound to the reviewed payload, not to the operator."""
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    approval = await raise_request(client, agent_id)
    await decide(client, approval["id"], APPROVER_ONE)
    await decide(client, approval["id"], APPROVER_TWO)

    swapped = await dispatch(
        client,
        agent_id,
        approval["id"],
        payload={"script": "Stop-Service -Name MSSQLSERVER"},
    )
    assert swapped.status_code == 409
    assert swapped.json()["detail"]["code"] == "approval_request_payload_mismatch"

    async with AsyncSessionLocal() as db:
        assert (await db.execute(select(Command))).first() is None
        stored = await db.get(ApprovalRequest, approval["id"])
        assert stored.status == ApprovalRequestStatus.approved

    # The reviewed payload still works, so the refusal was the mutation and not
    # a broken approval.
    assert (await dispatch(client, agent_id, approval["id"])).status_code == 200


@pytest.mark.asyncio
async def test_binding_digest_ignores_key_order_only(client):
    """Equivalent payloads match; a changed value does not."""
    payload = {"script": "Get-Service", "timeout_seconds": 30}
    reordered = {"timeout_seconds": 30, "script": "Get-Service"}
    changed = {"script": "Get-Service", "timeout_seconds": 31}
    assert binding_digest("a1", CommandKind.powershell, payload) == binding_digest(
        "a1", CommandKind.powershell, reordered
    )
    assert binding_digest("a1", CommandKind.powershell, payload) != binding_digest(
        "a1", CommandKind.powershell, changed
    )
    # The agent and kind are bound too: an approval is not portable.
    assert binding_digest("a1", CommandKind.powershell, payload) != binding_digest(
        "a2", CommandKind.powershell, payload
    )
    assert binding_digest("a1", CommandKind.powershell, payload) != binding_digest(
        "a1", CommandKind.shell, payload
    )


@pytest.mark.asyncio
async def test_expired_request_cannot_be_decided_or_spent(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    approval = await raise_request(client, agent_id)
    await decide(client, approval["id"], APPROVER_ONE)
    await decide(client, approval["id"], APPROVER_TWO)

    async with AsyncSessionLocal() as db:
        stored = await db.get(ApprovalRequest, approval["id"])
        stored.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await db.commit()

    spent = await dispatch(client, agent_id, approval["id"])
    assert spent.status_code == 409
    assert spent.json()["detail"]["code"] == "approval_request_expired"

    async with AsyncSessionLocal() as db:
        stored = await db.get(ApprovalRequest, approval["id"])
        assert stored.status == ApprovalRequestStatus.expired
        assert (await db.execute(select(Command))).first() is None
    assert "approval_request.expired" in await audit_actions()


@pytest.mark.asyncio
async def test_expiry_is_applied_on_read(client):
    """A lapsed request is never shown as actionable, sweeper or not."""
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    approval = await raise_request(client, agent_id)
    # One verdict already recorded, so the read that expires the request also
    # has to render the decisions it carries.
    assert (await decide(client, approval["id"], APPROVER_ONE)).status_code == 200
    async with AsyncSessionLocal() as db:
        stored = await db.get(ApprovalRequest, approval["id"])
        stored.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await db.commit()

    headers = await auth(client, APPROVER_ONE)
    listed = await client.get("/approval-requests?status=pending", headers=headers)
    assert listed.status_code == 200
    assert listed.json() == []

    read = await client.get(f"/approval-requests/{approval['id']}", headers=headers)
    assert read.status_code == 200, read.text
    assert read.json()["status"] == "expired"
    assert [entry["operator_email"] for entry in read.json()["decisions"]] == [
        APPROVER_ONE
    ]

    late = await decide(client, approval["id"], APPROVER_ONE)
    assert late.status_code == 409
    assert late.json()["detail"]["code"] == "approval_request_expired"


@pytest.mark.asyncio
async def test_approver_role_loss_invalidates_the_approval(client):
    """Authority must still exist when the approval is used, not only when given."""
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    approval = await raise_request(client, agent_id)
    await decide(client, approval["id"], APPROVER_ONE)
    await decide(client, approval["id"], APPROVER_TWO)

    # Revoke one approver's script permission after they approved.
    async with AsyncSessionLocal() as db:
        approver = (
            await db.execute(select(Operator).where(Operator.email == APPROVER_ONE))
        ).scalar_one()
        approver.script_execution_scope = None
        await db.commit()

    response = await dispatch(client, agent_id, approval["id"])
    assert response.status_code == 409
    assert (
        response.json()["detail"]["code"] == "approval_approver_no_longer_eligible"
    )
    async with AsyncSessionLocal() as db:
        assert (await db.execute(select(Command))).first() is None


@pytest.mark.asyncio
async def test_disabled_approver_no_longer_counts(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    approval = await raise_request(client, agent_id)
    await decide(client, approval["id"], APPROVER_ONE)
    await decide(client, approval["id"], APPROVER_TWO)

    async with AsyncSessionLocal() as db:
        approver = (
            await db.execute(select(Operator).where(Operator.email == APPROVER_TWO))
        ).scalar_one()
        approver.disabled = True
        await db.commit()

    response = await dispatch(client, agent_id, approval["id"])
    assert response.status_code == 409
    assert (
        response.json()["detail"]["code"] == "approval_approver_no_longer_eligible"
    )


@pytest.mark.asyncio
async def test_readonly_identity_cannot_approve(client):
    """Approval never launders authority the approver does not hold."""
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    approval = await raise_request(client, agent_id)

    async with AsyncSessionLocal() as db:
        approver = (
            await db.execute(select(Operator).where(Operator.email == APPROVER_ONE))
        ).scalar_one()
        approver.script_execution_scope = None
        await db.commit()

    response = await decide(client, approval["id"], APPROVER_ONE)
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "approver_script_permission_missing"


@pytest.mark.asyncio
async def test_requester_must_already_be_authorized(client):
    """An operator with no script permission cannot raise one to get it."""
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    async with AsyncSessionLocal() as db:
        requester = (
            await db.execute(select(Operator).where(Operator.email == REQUESTER))
        ).scalar_one()
        requester.script_execution_scope = None
        await db.commit()

    headers = await auth(client, REQUESTER)
    response = await client.post(
        "/approval-requests",
        json={
            "agent_id": agent_id,
            "kind": "powershell",
            "payload": SCRIPT_PAYLOAD,
            "reason": "Trying to get authority I do not have",
        },
        headers=headers,
    )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "approval_request_not_authorized"
    assert "approval_request.denied" in await audit_actions()


@pytest.mark.asyncio
async def test_another_operator_cannot_spend_someone_elses_approval(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    approval = await raise_request(client, agent_id)
    await decide(client, approval["id"], APPROVER_ONE)
    await decide(client, approval["id"], APPROVER_TWO)

    response = await dispatch(client, agent_id, approval["id"], actor=APPROVER_ONE)
    assert response.status_code == 409
    assert (
        response.json()["detail"]["code"] == "approval_request_requester_mismatch"
    )


# --------------------------------------------------------------------------- #
# Rejection, cancellation, and tenancy
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_rejection_is_terminal(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    approval = await raise_request(client, agent_id)

    rejected = await decide(client, approval["id"], APPROVER_ONE, verdict="reject")
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"

    late = await decide(client, approval["id"], APPROVER_TWO)
    assert late.status_code == 409
    assert late.json()["detail"]["code"] == "approval_request_not_pending"

    spent = await dispatch(client, agent_id, approval["id"])
    assert spent.status_code == 409
    assert spent.json()["detail"]["code"] == "approval_request_not_approved"


@pytest.mark.asyncio
async def test_requester_can_cancel_an_approved_request(client):
    """Withdrawn work must not leave a spendable approval behind."""
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    approval = await raise_request(client, agent_id)
    await decide(client, approval["id"], APPROVER_ONE)
    await decide(client, approval["id"], APPROVER_TWO)

    headers = await auth(client, REQUESTER)
    cancelled = await client.post(
        f"/approval-requests/{approval['id']}/cancel",
        json={"reason": "Incident resolved without the restart"},
        headers=headers,
    )
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"

    spent = await dispatch(client, agent_id, approval["id"])
    assert spent.status_code == 409
    assert spent.json()["detail"]["code"] == "approval_request_not_approved"


@pytest.mark.asyncio
async def test_requests_are_invisible_across_tenants(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    approval = await raise_request(client, agent_id)

    outsider = await auth(client, OUTSIDER)
    read = await client.get(f"/approval-requests/{approval['id']}", headers=outsider)
    assert read.status_code == 404
    assert read.json()["detail"]["code"] == "approval_request_not_found"

    listed = await client.get("/approval-requests", headers=outsider)
    assert listed.status_code == 200
    assert listed.json() == []

    decided = await decide(client, approval["id"], OUTSIDER)
    assert decided.status_code == 404


@pytest.mark.asyncio
async def test_approval_from_another_tenant_cannot_be_spent(client):
    """A foreign approval id is a 404, never an existence oracle."""
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    approval = await raise_request(client, agent_id)
    await decide(client, approval["id"], APPROVER_ONE)
    await decide(client, approval["id"], APPROVER_TWO)

    # A second tenant with its own agent and policy.
    other_id, _, other_agent = await provision(client)
    await create_policy(client, other_id)

    response = await dispatch(client, other_agent, approval["id"])
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "approval_request_not_found"


@pytest.mark.asyncio
async def test_offering_an_approval_where_none_is_required_is_refused(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id, kinds=("powershell",))
    approval = await raise_request(client, agent_id)
    await decide(client, approval["id"], APPROVER_ONE)
    await decide(client, approval["id"], APPROVER_TWO)

    # collect_inventory is not under the policy, so the approval is meaningless
    # here and must not be silently marked spent.
    headers = await auth(client, REQUESTER)
    response = await client.post(
        f"/agents/{agent_id}/commands",
        json={
            "kind": "collect_inventory",
            "payload": {},
            "approval_request_id": approval["id"],
        },
        headers=headers,
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "approval_not_required"
    async with AsyncSessionLocal() as db:
        stored = await db.get(ApprovalRequest, approval["id"])
    assert stored.status == ApprovalRequestStatus.approved


@pytest.mark.asyncio
async def test_request_for_an_ungoverned_kind_is_refused(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id, kinds=("shell",))
    headers = await auth(client, REQUESTER)
    response = await client.post(
        "/approval-requests",
        json={
            "agent_id": agent_id,
            "kind": "powershell",
            "payload": SCRIPT_PAYLOAD,
            "reason": "No policy governs this kind here",
        },
        headers=headers,
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "approval_not_required"


# --------------------------------------------------------------------------- #
# Bypasses
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_scheduled_task_under_policy_is_refused(client):
    """An unattended run cannot obtain two-person authorization, so it stops."""
    client_id, site_id, agent_id = await provision(client)
    await create_policy(client, client_id)

    async with AsyncSessionLocal() as db:
        db.add(
            ScheduledTask(
                name="Nightly spooler restart",
                kind=CommandKind.powershell,
                payload=SCRIPT_PAYLOAD,
                target_type=ScheduleTargetType.agent,
                target_id=agent_id,
                cron_expression="0 3 * * *",
                timezone="UTC",
                enabled=True,
                next_run_at=datetime.now(timezone.utc) - timedelta(minutes=1),
                concurrency_policy=ScheduleConcurrencyPolicy.skip,
                misfire_policy=ScheduleMisfirePolicy.run_once,
                created_by_email=REQUESTER,
            )
        )
        await db.commit()

    async with AsyncSessionLocal() as db:
        await dispatch_scheduled_tasks_once(db)
        await db.commit()

    async with AsyncSessionLocal() as db:
        commands = (await db.execute(select(Command))).scalars().all()
        task = (await db.execute(select(ScheduledTask))).scalar_one()
    assert commands == []
    assert task.last_status == "approval_required"
    assert "scheduled_task.approval_refused" in await audit_actions()


@pytest.mark.asyncio
async def test_interactive_shell_is_refused_under_a_script_policy(client):
    """An interactive shell has no reviewable payload, so it is refused outright."""
    client_id, _, agent_id = await provision(client, capabilities=("shell-session-v1",))
    await create_policy(client, client_id, kinds=("powershell",))

    headers = await auth(client, REQUESTER)
    response = await client.post(
        f"/agents/{agent_id}/shell-sessions",
        json={"shell": "powershell"},
        headers=headers,
    )
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "shell_session_requires_approval"


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_audit_evidence_is_complete_and_secret_free(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    approval = await raise_request(client, agent_id)
    await decide(client, approval["id"], APPROVER_ONE)
    await decide(client, approval["id"], APPROVER_TWO)
    assert (await dispatch(client, agent_id, approval["id"])).status_code == 200

    actions = await audit_actions()
    for expected in (
        "approval_policy.created",
        "approval_request.created",
        "approval_request.decision_recorded",
        "approval_gate.allowed",
        "command.dispatched",
    ):
        assert expected in actions, expected

    # The reviewed script is never committed to the chain: only key names, the
    # binding digest, and a digest of the operator's prose.
    script = SCRIPT_PAYLOAD["script"]
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(select(AuditEvent.detail))).scalars().all()
    blob = repr(rows)
    assert script not in blob
    assert "INC-4711" not in blob

    created = (await audit_details("approval_request.created"))[0]
    assert created["payload_keys"] == ["script"]
    assert created["payload_sha256"] == approval["payload_sha256"]
    assert "reason_sha256" in created and "reason" not in created

    async with AsyncSessionLocal() as db:
        ok, broken = await audit.verify_chain(db)
    assert ok, broken


@pytest.mark.asyncio
async def test_request_detail_links_the_command_it_authorized(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    approval = await raise_request(client, agent_id)
    await decide(client, approval["id"], APPROVER_ONE)
    await decide(client, approval["id"], APPROVER_TWO)
    dispatched = await dispatch(client, agent_id, approval["id"])
    assert dispatched.status_code == 200

    headers = await auth(client, APPROVER_ONE)
    detail = (
        await client.get(f"/approval-requests/{approval['id']}", headers=headers)
    ).json()
    assert detail["consumed_command_id"] == dispatched.json()["id"]
    assert detail["status"] == "consumed"
    assert {entry["operator_email"] for entry in detail["decisions"]} == {
        APPROVER_ONE,
        APPROVER_TWO,
    }


@pytest.mark.asyncio
async def test_reason_is_mandatory_and_bounded(client):
    client_id, _, agent_id = await provision(client)
    await create_policy(client, client_id)
    headers = await auth(client, REQUESTER)
    for reason in ("", "too short", "x" * 513, "has\u0007control"):
        response = await client.post(
            "/approval-requests",
            json={
                "agent_id": agent_id,
                "kind": "powershell",
                "payload": SCRIPT_PAYLOAD,
                "reason": reason,
            },
            headers=headers,
        )
        assert response.status_code == 422, reason
