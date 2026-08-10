# SPDX-License-Identifier: AGPL-3.0-only
"""Policy, validation, and audit tests for bounded event log access (issue #58)."""
from __future__ import annotations

import os
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_event_log_access.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from pydantic import ValidationError  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core.command_envelope import COMMAND_ENVELOPE_V3  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    AuditEvent,
    Command,
    CommandKind,
    CommandStatus,
    Operator,
    OperatorRole,
)
from app.schemas.schemas import CommandCreate  # noqa: E402


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                Operator(email="evt-admin@nodelink.test", password_hash=hash_password("admin-pass"), role=OperatorRole.admin),
                Operator(email="evt-op@nodelink.test", password_hash=hash_password("op-pass"), role=OperatorRole.operator),
            ]
        )
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test/api/v1") as value:
        yield value
    await engine.dispose()


async def auth(client, email="evt-admin@nodelink.test", password="admin-pass"):
    response = await client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def enroll(client, headers, capabilities=("event-log-query-v1",)):
    organization = (await client.post("/clients", json={"name": f"Evt {uuid4().hex}"}, headers=headers)).json()
    site = (await client.post("/sites", json={"client_id": organization["id"], "name": "HQ"}, headers=headers)).json()
    token = (await client.post("/enrollment-tokens", json={"site_id": site["id"]}, headers=headers)).json()["token"]
    response = await client.post(
        "/enroll",
        json={
            "enrollment_token": token,
            "hostname": "PC-EVT",
            "os": "windows",
            "supported_command_envelope_versions": [COMMAND_ENVELOPE_V3],
            "supported_capabilities": list(capabilities),
        },
    )
    assert response.status_code == 200, response.text
    return response.json(), site["id"]


def query_payload(**updates):
    payload = {"channel": "System", "time_window_seconds": 3600, "max_events": 100}
    payload.update(updates)
    return payload


def test_payload_is_strict_and_bounded():
    # Standard channel normalizes and defaults tier_ack to False.
    ok = CommandCreate(kind=CommandKind.query_event_log, payload=query_payload())
    assert ok.payload == {"channel": "System", "tier_ack": False, "time_window_seconds": 3600, "max_events": 100}

    # Off-allowlist channel is refused.
    with pytest.raises(ValidationError):
        CommandCreate(kind=CommandKind.query_event_log, payload=query_payload(channel="Microsoft-Windows-PowerShell/Operational"))

    # Elevated channel requires tier_ack; standard channel rejects it.
    with pytest.raises(ValidationError):
        CommandCreate(kind=CommandKind.query_event_log, payload=query_payload(channel="Security"))
    with pytest.raises(ValidationError):
        CommandCreate(kind=CommandKind.query_event_log, payload=query_payload(tier_ack=True))
    elevated = CommandCreate(kind=CommandKind.query_event_log, payload=query_payload(channel="Security", tier_ack=True))
    assert elevated.payload["tier_ack"] is True

    # Bounds and filters.
    with pytest.raises(ValidationError):
        CommandCreate(kind=CommandKind.query_event_log, payload=query_payload(max_events=0))
    with pytest.raises(ValidationError):
        CommandCreate(kind=CommandKind.query_event_log, payload=query_payload(time_window_seconds=10))
    with pytest.raises(ValidationError):
        CommandCreate(kind=CommandKind.query_event_log, payload=query_payload(levels=[9]))
    with pytest.raises(ValidationError):
        CommandCreate(kind=CommandKind.query_event_log, payload=query_payload(cursor=-1))
    with pytest.raises(ValidationError):
        CommandCreate(kind=CommandKind.query_event_log, payload=query_payload(unexpected="x"))

    filtered = CommandCreate(
        kind=CommandKind.query_event_log,
        payload=query_payload(channel="Security", tier_ack=True, providers=["Microsoft-Windows-Security-Auditing"], levels=[2, 3], event_ids=[4624], cursor=42),
    )
    assert filtered.payload["providers"] == ["Microsoft-Windows-Security-Auditing"]
    assert filtered.payload["cursor"] == 42


@pytest.mark.asyncio
async def test_dispatch_requires_admin_and_records_query_scope(client):
    admin = await auth(client)
    operator = await auth(client, "evt-op@nodelink.test", "op-pass")
    enrollment, _ = await enroll(client, admin)
    agent_id = enrollment["agent_id"]

    denied = await client.post(f"/agents/{agent_id}/commands", headers=operator, json={"kind": "query_event_log", "payload": query_payload()})
    assert denied.status_code == 403
    assert denied.json()["detail"]["code"] == "event_log_query_not_authorized"

    allowed = await client.post(
        f"/agents/{agent_id}/commands",
        headers=admin,
        json={"kind": "query_event_log", "payload": query_payload(channel="Security", tier_ack=True, levels=[2, 3], cursor=17)},
    )
    assert allowed.status_code == 200, allowed.text
    command_id = allowed.json()["id"]

    async with AsyncSessionLocal() as db:
        stored = await db.get(Command, command_id)
        assert stored.status == CommandStatus.queued
        scope = (await db.execute(select(AuditEvent).where(AuditEvent.action == "event_log_query.dispatched"))).scalars().all()
        assert len(scope) == 1
        detail = scope[0].detail
        assert detail["channel"] == "Security"
        assert detail["tier"] == "elevated"
        assert detail["level_filter"] is True
        assert detail["provider_filter"] is False
        assert detail["paginated"] is True
        # No event contents are ever recorded in the audit chain.
        assert "records" not in detail and "message" not in detail


@pytest.mark.asyncio
async def test_agent_without_capability_fails_closed(client):
    admin = await auth(client)
    old_agent, _ = await enroll(client, admin, capabilities=())
    unsupported = await client.post(
        f"/agents/{old_agent['agent_id']}/commands",
        headers=admin,
        json={"kind": "query_event_log", "payload": query_payload()},
    )
    assert unsupported.status_code == 409
    assert unsupported.json()["detail"]["code"] == "agent_capability_unsupported"
