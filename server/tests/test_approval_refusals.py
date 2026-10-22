# SPDX-License-Identifier: AGPL-3.0-only
"""Refusal paths of the approval and emergency-override APIs (issue #284).

Each test drives one ``raise HTTPException`` branch the workflow suites never
reach: unknown policies, requests, overrides and agents; payloads the
dispatcher would refuse; the per-operator open-request ceiling; terminal
requests; and the defensive branches that stand behind a concurrent writer.

Two of those defensive branches exist only for a race SQLite cannot interleave
inside one test, so the race is simulated directly: the agent row disappears
underneath a live request, and an approver's stale read misses their own
earlier decision. Both assert the handler fails with its documented code
rather than a 500.
"""
from __future__ import annotations

import os
from uuid import uuid4

os.environ.setdefault(
    "DATABASE_URL", "sqlite+aiosqlite:///./test_approval_refusals.db"
)
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
_LOGIN = os.environ.setdefault("NODELINK_TEST_LOGIN", "op-pass")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import delete, select  # noqa: E402

from app.api import approvals as approvals_api  # noqa: E402
from app.core import approvals as approvals_core  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V3  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    ClientRole,
    Operator,
    OperatorClientMembership,
    OperatorRole,
    ScriptExecutionScope,
)

REQUESTER = "refusal-req@nodelink.test"  # operator, client_operator
APPROVER = "refusal-appr@nodelink.test"  # operator, client_operator
PLATFORM = "refusal-platform@nodelink.test"  # platform admin

MISSING_ID = "00000000-0000-4000-8000-000000000000"
SCRIPT_PAYLOAD = {"script": "Restart-Service -Name Spooler"}
REASON = "Spooler is wedged on the print server, INC-4711"
JUSTIFICATION = "Print server down for 40 users, INC-9001, approvers unreachable"
# 20k two-byte characters: 40 KB as canonical UTF-8, under the envelope's own
# ceiling, but 120 KB once ``json.dumps`` escapes them to ``\\uXXXX`` for the
# handler's stored-size check -- which is the check this payload trips.
OVERSIZED_WHEN_ESCAPED = {"script": "é" * 20_000}
FLOAT_PAYLOAD = {"script": "Get-Process", "timeout": 1.5}


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                Operator(
                    email=email,
                    password_hash=hash_password(_LOGIN),
                    role=role,
                    is_platform_admin=email == PLATFORM,
                    script_execution_scope=ScriptExecutionScope.global_,
                )
                for email, role in (
                    (REQUESTER, OperatorRole.operator),
                    (APPROVER, OperatorRole.operator),
                    (PLATFORM, OperatorRole.admin),
                )
            ]
        )
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://t/api/v1"
    ) as value:
        yield value
    await engine.dispose()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
async def auth(client, email: str = PLATFORM) -> dict[str, str]:
    response = await client.post(
        "/auth/login", json={"email": email, "password": _LOGIN}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


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


async def provision(client) -> tuple[str, str]:
    """A tenant with one enrolled agent; requester and approver admitted."""
    headers = await auth(client)
    org = (
        await client.post(
            "/clients", json={"name": f"Refusals {uuid4().hex}"}, headers=headers
        )
    ).json()
    site = (
        await client.post(
            "/sites", json={"client_id": org["id"], "name": "HQ"}, headers=headers
        )
    ).json()
    token = (
        await client.post(
            "/enrollment-tokens", json={"site_id": site["id"]}, headers=headers
        )
    ).json()["token"]
    enrollment = (
        await client.post(
            "/enroll",
            json={
                "enrollment_token": token,
                "hostname": "REFUSAL-PC",
                "os": "windows",
                "supported_command_envelope_versions": [COMMAND_ENVELOPE_V3],
                "supported_capabilities": [],
            },
        )
    ).json()
    await grant_membership(REQUESTER, org["id"], ClientRole.client_operator)
    await grant_membership(APPROVER, org["id"], ClientRole.client_operator)
    return org["id"], enrollment["agent_id"]


def policy_body(client_id: str, name: str = "Dual control") -> dict:
    return {
        "name": name,
        "scope": "client",
        "scope_id": client_id,
        "command_kinds": ["powershell"],
        "required_approvals": 2,
        "request_ttl_seconds": 3600,
    }


async def create_policy(client, client_id: str) -> dict:
    response = await client.post(
        "/approval-policies", json=policy_body(client_id), headers=await auth(client)
    )
    assert response.status_code == 201, response.text
    return response.json()


async def raise_request(client, agent_id: str, payload=None):
    return await client.post(
        "/approval-requests",
        json={
            "agent_id": agent_id,
            "kind": "powershell",
            "payload": SCRIPT_PAYLOAD if payload is None else payload,
            "reason": REASON,
        },
        headers=await auth(client, REQUESTER),
    )


async def governed_request(client) -> tuple[str, str]:
    """A pending two-approval request; returns (request_id, agent_id)."""
    client_id, agent_id = await provision(client)
    await create_policy(client, client_id)
    response = await raise_request(client, agent_id)
    assert response.status_code == 201, response.text
    return response.json()["id"], agent_id


async def act(client, request_id: str, verb: str, actor: str):
    return await client.post(
        f"/approval-requests/{request_id}/{verb}",
        json={"reason": f"Reviewed the change window for INC-4711 ({verb})"},
        headers=await auth(client, actor),
    )


# --------------------------------------------------------------------------- #
# Policies
# --------------------------------------------------------------------------- #
async def test_duplicate_policy_name_in_one_scope_conflicts(client):
    client_id, _ = await provision(client)
    await create_policy(client, client_id)

    response = await client.post(
        "/approval-policies",
        json=policy_body(client_id, name="  DUAL CONTROL "),
        headers=await auth(client),
    )

    assert response.status_code == 409
    assert response.json()["detail"] == {"code": "approval_policy_name_conflict"}


@pytest.mark.parametrize(
    "method, body",
    [("PATCH", {"enabled": False}), ("DELETE", None)],
    ids=["update", "delete"],
)
async def test_unknown_policy_is_404(client, method, body):
    response = await client.request(
        method,
        f"/approval-policies/{MISSING_ID}",
        json=body,
        headers=await auth(client),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == {"code": "approval_policy_not_found"}


# --------------------------------------------------------------------------- #
# Raising a request
# --------------------------------------------------------------------------- #
async def test_unknown_request_is_404(client):
    response = await client.get(
        f"/approval-requests/{MISSING_ID}", headers=await auth(client)
    )

    assert response.status_code == 404
    assert response.json()["detail"] == {"code": "approval_request_not_found"}


async def test_request_for_an_unknown_agent_is_404(client):
    response = await raise_request(client, MISSING_ID)

    assert response.status_code == 404
    assert response.json()["detail"] == {"code": "agent_not_found"}


@pytest.mark.parametrize(
    "payload, code",
    [
        (FLOAT_PAYLOAD, "command_payload_invalid"),
        (OVERSIZED_WHEN_ESCAPED, "command_payload_too_large"),
    ],
    ids=["float", "oversized"],
)
async def test_request_refuses_a_payload_dispatch_would_refuse(client, payload, code):
    _, agent_id = await provision(client)

    response = await raise_request(client, agent_id, payload=payload)

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == code


async def test_request_refused_at_the_open_request_ceiling(client, monkeypatch):
    monkeypatch.setattr(approvals_api, "MAX_OPEN_REQUESTS_PER_OPERATOR", 1)
    _, agent_id = await governed_request(client)

    response = await raise_request(client, agent_id)

    assert response.status_code == 429
    assert response.json()["detail"] == {
        "code": "approval_request_limit_reached",
        "outstanding": 1,
        "limit": 1,
    }


# --------------------------------------------------------------------------- #
# Deciding and cancelling
# --------------------------------------------------------------------------- #
async def test_decision_on_a_request_whose_agent_vanished_is_404(client):
    """The agent row is deleted underneath a live request (no ORM cascade)."""
    request_id, agent_id = await governed_request(client)
    async with AsyncSessionLocal() as db:
        await db.execute(delete(Agent).where(Agent.id == agent_id))
        await db.commit()

    response = await act(client, request_id, "approve", APPROVER)

    assert response.status_code == 404
    assert response.json()["detail"] == {"code": "approval_request_not_found"}


async def test_lost_decision_race_maps_to_already_recorded(client, monkeypatch):
    """A stale read misses the approver's first decision; the constraint holds."""
    request_id, _ = await governed_request(client)
    assert (await act(client, request_id, "approve", APPROVER)).status_code == 200

    original = approvals_core.decision_refusal
    monkeypatch.setattr(
        approvals_core,
        "decision_refusal",
        lambda request, decisions, operator, now: original(request, [], operator, now),
    )

    response = await act(client, request_id, "approve", APPROVER)

    assert response.status_code == 409
    assert response.json()["detail"] == {"code": "approval_already_recorded"}


async def test_cancelling_a_closed_request_conflicts(client):
    request_id, _ = await governed_request(client)
    assert (await act(client, request_id, "cancel", REQUESTER)).status_code == 200

    response = await act(client, request_id, "cancel", REQUESTER)

    assert response.status_code == 409
    assert response.json()["detail"] == {"code": "approval_request_not_pending"}


# --------------------------------------------------------------------------- #
# Emergency overrides
# --------------------------------------------------------------------------- #
async def test_unknown_emergency_override_is_404(client):
    response = await client.get(
        f"/emergency-overrides/{MISSING_ID}", headers=await auth(client)
    )

    assert response.status_code == 404
    assert response.json()["detail"] == {"code": "emergency_override_not_found"}


@pytest.mark.parametrize(
    "known_agent, payload, status_code, code",
    [
        (False, SCRIPT_PAYLOAD, 404, "agent_not_found"),
        (True, FLOAT_PAYLOAD, 422, "command_payload_invalid"),
        (True, OVERSIZED_WHEN_ESCAPED, 422, "command_payload_too_large"),
    ],
    ids=["unknown-agent", "float", "oversized"],
)
async def test_override_activation_refusals(
    client, known_agent, payload, status_code, code
):
    agent_id = (await provision(client))[1] if known_agent else MISSING_ID

    response = await client.post(
        "/emergency-overrides",
        json={
            "agent_id": agent_id,
            "kind": "powershell",
            "payload": payload,
            "justification": JUSTIFICATION,
        },
        headers=await auth(client),
    )

    assert response.status_code == status_code
    assert response.json()["detail"]["code"] == code
