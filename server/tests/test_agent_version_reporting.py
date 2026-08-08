# SPDX-License-Identifier: AGPL-3.0-only
"""Heartbeat-reported agent version tests (issue #179).

Behavior under test:
  - every authenticated beat may carry the running ``agent_version``; a changed
    value updates ``Agent.agent_version`` and emits exactly one bounded audit
    event carrying the previous and current values
  - an unchanged value updates nothing and emits nothing, so a steady-state
    fleet does not generate repeated events
  - a lower version (rollback/downgrade) is recorded like any other change,
    because a fleet that silently rolled back is exactly what an operator needs
    to see
  - an in-place upgrade refreshes the version with no re-enrollment, no new
    token, no identity change, and no inventory upload
  - the management endpoint list and detail views return the refreshed value
  - the documented compatibility policy: absent is accepted and leaves the
    stored value untouched (pre-v0.1.4 agents), while empty, oversized, or
    malformed values are rejected with 422
  - quarantined and revoked agents stay fail closed: neither can move the
    stored version

Run just this file:  pytest tests/test_agent_version_reporting.py -q
"""
from __future__ import annotations

import os
from uuid import uuid4

os.environ.setdefault(
    "DATABASE_URL", "sqlite+aiosqlite:///./test_agent_version_reporting.db"
)
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.main import app  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V2  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    AuditEvent,
    Operator,
    OperatorRole,
    ScriptExecutionScope,
)
from app.schemas.schemas import MAX_AGENT_VERSION_LENGTH  # noqa: E402


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        db.add(
            Operator(
                email="version-admin@nodelink.test",
                password_hash=hash_password("admin-pass"),
                role=OperatorRole.admin,
                script_execution_scope=ScriptExecutionScope.global_,
            )
        )
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        yield c
    await engine.dispose()


async def _operator_auth(c) -> dict:
    r = await c.post(
        "/auth/login",
        json={"email": "version-admin@nodelink.test", "password": "admin-pass"},
    )
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


async def _enroll(c, op_auth, agent_version: str = "0.1.2") -> tuple[str, str]:
    """Provision client/site/token and enroll one agent at agent_version."""
    cl = (
        await c.post(
            "/clients", json={"name": f"Version Clinic {uuid4().hex}"}, headers=op_auth
        )
    ).json()
    st = (
        await c.post(
            "/sites", json={"client_id": cl["id"], "name": "HQ"}, headers=op_auth
        )
    ).json()
    et = (
        await c.post(
            "/enrollment-tokens", json={"site_id": st["id"], "max_uses": 5}, headers=op_auth
        )
    ).json()
    r = await c.post(
        "/enroll",
        json={
            "enrollment_token": et["token"],
            "hostname": "PC-VERSION",
            "os": "windows",
            "agent_version": agent_version,
            "supported_command_envelope_versions": [COMMAND_ENVELOPE_V2],
        },
    )
    assert r.status_code == 200
    body = r.json()
    return body["agent_id"], body["agent_token"]


async def _beat(c, agent_token: str, agent_version: str | None = None):
    body: dict = {
        "cpu_percent": 5.0,
        "supported_command_envelope_versions": [COMMAND_ENVELOPE_V2],
    }
    if agent_version is not None:
        body["agent_version"] = agent_version
    return await c.post(
        "/heartbeat", json=body, headers={"Authorization": f"Bearer {agent_token}"}
    )


async def _stored_version(agent_id: str) -> str:
    async with AsyncSessionLocal() as db:
        agent = await db.get(Agent, agent_id)
        return agent.agent_version


async def _version_events() -> list[dict]:
    async with AsyncSessionLocal() as db:
        rows = (
            await db.execute(
                select(AuditEvent)
                .where(AuditEvent.action == "agent.version_changed")
                .order_by(AuditEvent.seq)
            )
        ).scalars()
        return [row.detail for row in rows]


# --------------------------------------------------------------------------- #
# Refresh on upgrade
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_in_place_upgrade_refreshes_version_on_next_heartbeat(client):
    """v0.1.2 → v0.1.3 → v0.1.4 with the same agent ID and credentials."""
    op = await _operator_auth(client)
    agent_id, agent_token = await _enroll(client, op, agent_version="0.1.2")
    assert await _stored_version(agent_id) == "0.1.2"

    for upgraded_to in ("0.1.3", "0.1.4"):
        r = await _beat(client, agent_token, upgraded_to)
        assert r.status_code == 200
        # No re-enrollment: the same credential keeps working and the agent ID
        # is unchanged across both upgrades.
        assert await _stored_version(agent_id) == upgraded_to

    events = await _version_events()
    assert [(e["previous"], e["current"]) for e in events] == [
        ("0.1.2", "0.1.3"),
        ("0.1.3", "0.1.4"),
    ]


@pytest.mark.asyncio
async def test_refreshed_version_is_returned_by_list_and_detail_views(client):
    op = await _operator_auth(client)
    agent_id, agent_token = await _enroll(client, op, agent_version="0.1.2")

    assert (await _beat(client, agent_token, "0.1.4")).status_code == 200

    detail = (await client.get(f"/endpoints/{agent_id}", headers=op)).json()
    assert detail["agent_version"] == "0.1.4"

    listing = (await client.get("/endpoints", headers=op)).json()
    row = next(item for item in listing["items"] if item["id"] == agent_id)
    assert row["agent_version"] == "0.1.4"

    # The enrollment-management view of the same agent agrees.
    agent_view = (await client.get(f"/agents/{agent_id}", headers=op)).json()
    assert agent_view["agent_version"] == "0.1.4"


@pytest.mark.asyncio
async def test_version_refresh_does_not_depend_on_an_inventory_upload(client):
    """No inventory is ever submitted here; the beat alone refreshes state."""
    op = await _operator_auth(client)
    agent_id, agent_token = await _enroll(client, op, agent_version="0.1.2")

    assert (await _beat(client, agent_token, "0.1.4")).status_code == 200
    assert await _stored_version(agent_id) == "0.1.4"

    async with AsyncSessionLocal() as db:
        stored_inventory = (
            await db.execute(select(AuditEvent.action).where(
                AuditEvent.action == "inventory.received"
            ))
        ).scalars().all()
    assert stored_inventory == []


@pytest.mark.asyncio
async def test_agent_enrolled_without_a_version_gets_one_from_the_first_beat(client):
    op = await _operator_auth(client)
    agent_id, agent_token = await _enroll(client, op, agent_version="")
    assert await _stored_version(agent_id) == ""

    assert (await _beat(client, agent_token, "0.1.4")).status_code == 200
    assert await _stored_version(agent_id) == "0.1.4"
    assert await _version_events() == [{"previous": "", "current": "0.1.4"}]


# --------------------------------------------------------------------------- #
# Bounded auditing
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_unchanged_version_emits_no_repeated_audit_events(client):
    op = await _operator_auth(client)
    agent_id, agent_token = await _enroll(client, op, agent_version="0.1.2")

    for _ in range(5):
        assert (await _beat(client, agent_token, "0.1.2")).status_code == 200
    assert await _version_events() == []

    # One change, then more steady-state beats: still exactly one event.
    assert (await _beat(client, agent_token, "0.1.4")).status_code == 200
    for _ in range(5):
        assert (await _beat(client, agent_token, "0.1.4")).status_code == 200
    assert await _version_events() == [{"previous": "0.1.2", "current": "0.1.4"}]
    assert await _stored_version(agent_id) == "0.1.4"


@pytest.mark.asyncio
async def test_rollback_to_an_earlier_version_is_recorded_not_suppressed(client):
    op = await _operator_auth(client)
    agent_id, agent_token = await _enroll(client, op, agent_version="0.1.4")

    assert (await _beat(client, agent_token, "0.1.3")).status_code == 200
    assert await _stored_version(agent_id) == "0.1.3"
    assert await _version_events() == [{"previous": "0.1.4", "current": "0.1.3"}]


# --------------------------------------------------------------------------- #
# Compatibility policy
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_absent_version_is_accepted_and_leaves_the_stored_value(client):
    """Agents released before this field existed must keep beating normally."""
    op = await _operator_auth(client)
    agent_id, agent_token = await _enroll(client, op, agent_version="0.1.2")

    r = await _beat(client, agent_token, None)
    assert r.status_code == 200
    assert await _stored_version(agent_id) == "0.1.2"
    assert await _version_events() == []


@pytest.mark.asyncio
async def test_empty_oversized_and_malformed_versions_are_rejected(client):
    op = await _operator_auth(client)
    agent_id, agent_token = await _enroll(client, op, agent_version="0.1.2")

    rejected = [
        "",
        "   ",
        "x" * (MAX_AGENT_VERSION_LENGTH + 1),
        "0.1.4 (dev build)",
        "0.1.4\nagent_version: 0.1.5",
        "../../etc/passwd",
        "-0.1.4",
    ]
    for value in rejected:
        r = await _beat(client, agent_token, value)
        assert r.status_code == 422, f"{value!r} was accepted"

    # A rejected beat must not have moved any stored state.
    assert await _stored_version(agent_id) == "0.1.2"
    assert await _version_events() == []


@pytest.mark.asyncio
async def test_representative_release_versions_are_accepted(client):
    op = await _operator_auth(client)
    agent_id, agent_token = await _enroll(client, op, agent_version="0.1.2")

    for value in ("0.1.4", "1.0.0-rc.1", "0.1.4+build.7", "0.1.0-dev"):
        assert (await _beat(client, agent_token, value)).status_code == 200
        assert await _stored_version(agent_id) == value


# --------------------------------------------------------------------------- #
# Fail closed
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_quarantined_agent_cannot_move_the_stored_version(client):
    op = await _operator_auth(client)
    agent_id, agent_token = await _enroll(client, op, agent_version="0.1.2")

    r = await client.post(
        f"/agents/{agent_id}/quarantine",
        json={"reason": "suspected compromise"},
        headers=op,
    )
    assert r.status_code == 200

    beat = await _beat(client, agent_token, "0.1.4")
    assert beat.status_code == 200
    assert beat.json()["trust_state"] == "quarantined"
    assert await _stored_version(agent_id) == "0.1.2"
    assert await _version_events() == []

    # Restoring trust lets the next beat refresh the version normally.
    assert (
        await client.post(
            f"/agents/{agent_id}/restore", json={"reason": "cleared"}, headers=op
        )
    ).status_code == 200
    assert (await _beat(client, agent_token, "0.1.4")).status_code == 200
    assert await _stored_version(agent_id) == "0.1.4"


@pytest.mark.asyncio
async def test_revoked_agent_cannot_report_a_version(client):
    op = await _operator_auth(client)
    agent_id, agent_token = await _enroll(client, op, agent_version="0.1.2")

    r = await client.post(
        f"/agents/{agent_id}/revoke", json={"reason": "decommissioned"}, headers=op
    )
    assert r.status_code == 200

    beat = await _beat(client, agent_token, "0.1.4")
    assert beat.status_code == 401
    assert await _stored_version(agent_id) == "0.1.2"
    assert await _version_events() == []


@pytest.mark.asyncio
async def test_unauthenticated_beat_cannot_report_a_version(client):
    op = await _operator_auth(client)
    agent_id, _ = await _enroll(client, op, agent_version="0.1.2")

    r = await client.post(
        "/heartbeat",
        json={
            "agent_version": "0.1.4",
            "supported_command_envelope_versions": [COMMAND_ENVELOPE_V2],
        },
        headers={"Authorization": "Bearer not-a-real-token"},
    )
    assert r.status_code == 401
    assert await _stored_version(agent_id) == "0.1.2"
