# SPDX-License-Identifier: AGPL-3.0-only
"""Policy, persistence, compatibility, and recovery tests for issue #60."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_power_operations.db")
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
from app.core.scheduler import dispatch_scheduled_tasks_once  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    AuditEvent,
    Command,
    CommandKind,
    CommandStatus,
    Operator,
    OperatorRole,
    ScheduleConcurrencyPolicy,
    ScheduleMisfirePolicy,
    ScheduleTargetType,
    ScheduledTask,
)
from app.schemas.schemas import CommandCreate  # noqa: E402
from app.schemas.scheduled_tasks import ScheduledTaskCreate  # noqa: E402


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                Operator(email="power-admin@nodelink.test", password_hash=hash_password("admin-pass"), role=OperatorRole.admin),
                Operator(email="power-op@nodelink.test", password_hash=hash_password("op-pass"), role=OperatorRole.operator),
            ]
        )
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test/api/v1") as value:
        yield value
    await engine.dispose()


async def auth(client, email="power-admin@nodelink.test", password="admin-pass"):
    response = await client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def enroll(client, headers, capabilities=("power-operations-v1",)):
    organization = (await client.post("/clients", json={"name": f"Power {uuid4().hex}"}, headers=headers)).json()
    site = (await client.post("/sites", json={"client_id": organization["id"], "name": "HQ"}, headers=headers)).json()
    token = (await client.post("/enrollment-tokens", json={"site_id": site["id"]}, headers=headers)).json()["token"]
    response = await client.post(
        "/enroll",
        json={
            "enrollment_token": token,
            "hostname": "PC-POWER",
            "os": "windows",
            "supported_command_envelope_versions": [COMMAND_ENVELOPE_V3],
            "supported_capabilities": list(capabilities),
        },
    )
    assert response.status_code == 200, response.text
    return response.json(), site["id"]


async def heartbeat(client, enrollment, logged_in_user):
    response = await client.post(
        "/heartbeat",
        headers={"Authorization": f"Bearer {enrollment['agent_token']}"},
        json={
            "logged_in_user": logged_in_user,
            "supported_command_envelope_versions": [COMMAND_ENVELOPE_V3],
            "supported_capabilities": ["power-operations-v1"],
        },
    )
    assert response.status_code == 200, response.text
    return response


async def maintenance_window(client, headers, agent_id, *, seconds=1800):
    now = datetime.now(timezone.utc)
    response = await client.post(
        "/monitoring/maintenance-windows",
        headers=headers,
        json={
            "name": "Approved power maintenance",
            "scope": "agent",
            "scope_id": agent_id,
            "starts_at": (now - timedelta(minutes=1)).isoformat(),
            "ends_at": (now + timedelta(seconds=seconds)).isoformat(),
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def power_payload(**updates):
    payload = {
        "confirm": True,
        "reason": "Approved operating system maintenance",
        "delay_seconds": 60,
        "user_consent": "confirmed",
    }
    payload.update(updates)
    return payload


@pytest.mark.parametrize(
    "updates",
    [
        {"confirm": False},
        {"reason": "short"},
        {"reason": "approved maintenance\nshutdown"},
        {"reason": "🙂" * 200},
        {"delay_seconds": 29},
        {"delay_seconds": 3601},
        {"user_consent": "assumed"},
        {"script": "shutdown /s"},
    ],
)
def test_power_payload_is_strict(updates):
    with pytest.raises(ValidationError):
        CommandCreate(kind="reboot", payload=power_payload(**updates))


def test_recurring_power_operations_are_refused():
    with pytest.raises(ValidationError):
        ScheduledTaskCreate(
            name="unsafe recurring reboot",
            target_type="agent",
            target_id=str(uuid4()),
            cron_expression="0 * * * *",
            kind="reboot",
            payload=power_payload(),
        )


@pytest.mark.asyncio
async def test_scheduler_defense_in_depth_refuses_legacy_power_task(client):
    admin = await auth(client)
    enrollment, _ = await enroll(client, admin)
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        task = ScheduledTask(
            name="legacy unsafe reboot",
            enabled=True,
            target_type=ScheduleTargetType.agent,
            target_id=enrollment["agent_id"],
            cron_expression="0 * * * *",
            timezone="UTC",
            kind=CommandKind.reboot,
            payload=power_payload(),
            concurrency_policy=ScheduleConcurrencyPolicy.skip,
            misfire_policy=ScheduleMisfirePolicy.run_once,
            next_run_at=now - timedelta(minutes=1),
        )
        db.add(task)
        await db.commit()
        result = await dispatch_scheduled_tasks_once(db, now=now)
        await db.refresh(task)
        assert result == {"dispatched": 0, "skipped": 1}
        assert task.last_status == "power_operation_refused"
        commands = (await db.execute(select(Command))).scalars().all()
        assert commands == []


@pytest.mark.asyncio
async def test_dispatch_requires_admin_capability_window_and_matching_consent(client):
    admin = await auth(client)
    operator = await auth(client, "power-op@nodelink.test", "op-pass")
    enrollment, _ = await enroll(client, admin)
    agent_id = enrollment["agent_id"]
    await heartbeat(client, enrollment, r"NODELINK\user")

    denied_role = await client.post(f"/agents/{agent_id}/commands", headers=operator, json={"kind": "reboot", "payload": power_payload()})
    assert denied_role.status_code == 403
    assert denied_role.json()["detail"]["code"] == "power_operation_not_authorized"

    no_window = await client.post(f"/agents/{agent_id}/commands", headers=admin, json={"kind": "shutdown", "payload": power_payload()})
    assert no_window.status_code == 409
    assert no_window.json()["detail"]["code"] == "power_operation_maintenance_window_required"

    window = await maintenance_window(client, admin, agent_id)
    no_consent = await client.post(
        f"/agents/{agent_id}/commands",
        headers=admin,
        json={"kind": "shutdown", "payload": power_payload(user_consent="no_user_session")},
    )
    assert no_consent.status_code == 409
    assert no_consent.json()["detail"]["code"] == "power_operation_user_consent_required"

    allowed = await client.post(f"/agents/{agent_id}/commands", headers=admin, json={"kind": "reboot", "payload": power_payload()})
    assert allowed.status_code == 200, allowed.text
    command = allowed.json()
    assert command["payload"]["maintenance_window_id"] == window["id"]
    assert command["payload"]["user_present_at_dispatch"] is True

    async with AsyncSessionLocal() as db:
        stored = await db.get(Command, command["id"])
        dispatch_event = await db.get(AuditEvent, stored.dispatch_audit_event_id)
        assert stored.status == CommandStatus.queued
        assert dispatch_event.action == "command.dispatched"
        denied = (await db.execute(select(AuditEvent).where(AuditEvent.action == "command.authorization_denied"))).scalars().all()
        assert any(event.detail["reason"] == "power_operation_maintenance_window_required" for event in denied)


@pytest.mark.asyncio
async def test_mixed_version_offline_pickup_expiry_and_cancel(client):
    admin = await auth(client)
    old_agent, _ = await enroll(client, admin, capabilities=())
    unsupported = await client.post(
        f"/agents/{old_agent['agent_id']}/commands",
        headers=admin,
        json={"kind": "cancel_power_action", "payload": {"confirm": True, "reason": "Cancel unsafe pending action"}},
    )
    assert unsupported.status_code == 409
    assert unsupported.json()["detail"]["code"] == "agent_capability_unsupported"

    enrollment, _ = await enroll(client, admin)
    agent_id = enrollment["agent_id"]
    cancel = await client.post(
        f"/agents/{agent_id}/commands",
        headers=admin,
        json={"kind": "cancel_power_action", "payload": {"confirm": True, "reason": "Cancel unsafe pending action"}},
    )
    assert cancel.status_code == 200
    command_id = cancel.json()["id"]
    pickup = await heartbeat(client, enrollment, None)
    assert [item["id"] for item in pickup.json()["pending_commands"]] == [command_id]

    # A queued command that expires while the endpoint is offline is never delivered.
    second = await client.post(
        f"/agents/{agent_id}/commands",
        headers=admin,
        json={"kind": "cancel_power_action", "payload": {"confirm": True, "reason": "Cancel another pending action"}},
    )
    async with AsyncSessionLocal() as db:
        stored = await db.get(Command, second.json()["id"])
        stored.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await db.commit()
    expired_pickup = await heartbeat(client, enrollment, None)
    assert second.json()["id"] not in {item["id"] for item in expired_pickup.json()["pending_commands"]}
    async with AsyncSessionLocal() as db:
        assert (await db.get(Command, second.json()["id"])).status == CommandStatus.expired
