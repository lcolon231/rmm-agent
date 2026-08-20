# SPDX-License-Identifier: AGPL-3.0-only
"""MeshCentral remote-desktop launch contract tests (issue #62).

Behavior under test — the authorized, audited, fail-closed *launch* contract,
all against a deterministic FakeMeshCentralClient (there is no live MeshCentral
in CI):
  - provider disabled refuses every launch (fail closed) and audits the denial
  - authorization: readonly and an operator without arbitrary-script scope are
    refused; an operator with scope may launch
  - agent/mapping gates: untrusted agent, missing/stale/conflict mapping all
    refuse with distinct codes and audit
  - success mints a single-use login_url returned only on 201, never on GET,
    and records launch_requested -> session_launched
  - MeshCentral unavailable fails closed with 503 and audits launch_failed
  - per-operator rate limiting; ownership 404 oracle; idempotent close

Run just this file:  pytest tests/test_meshcentral_launch.py -q
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_meshcentral_launch.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.main import app
from tests._tenancy import grant_all_memberships  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V2  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core import meshcentral as mc  # noqa: E402
from app.api.meshcentral import get_meshcentral_client  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    AgentMeshMapping,
    AgentTrustState,
    AuditEvent,
    MeshMappingOrigin,
    MeshMappingState,
    Operator,
    OperatorRole,
    ScriptExecutionScope,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


@pytest_asyncio.fixture
async def env(monkeypatch):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add(Operator(
            email="mc-op@nodelink.test",
            password_hash=hash_password("op-pass"),
            role=OperatorRole.operator,
            script_execution_scope=ScriptExecutionScope.global_,
        ))
        db.add(Operator(
            email="mc-op2@nodelink.test",
            password_hash=hash_password("op2-pass"),
            role=OperatorRole.operator,
            script_execution_scope=ScriptExecutionScope.global_,
        ))
        db.add(Operator(
            email="mc-noscope@nodelink.test",
            password_hash=hash_password("noscope-pass"),
            role=OperatorRole.operator,
            script_execution_scope=None,
        ))
        db.add(Operator(
            email="mc-viewer@nodelink.test",
            password_hash=hash_password("viewer-pass"),
            role=OperatorRole.readonly,
        ))
        await grant_all_memberships(db)
        await db.commit()

    # Provider enabled + a Fake client injected for every test; individual tests
    # flip these to exercise the disabled/unavailable paths.
    monkeypatch.setattr(settings, "meshcentral_provider", "enabled")
    fake = mc.FakeMeshCentralClient()
    app.dependency_overrides[get_meshcentral_client] = lambda: fake

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        yield c, fake
    app.dependency_overrides.pop(get_meshcentral_client, None)
    await engine.dispose()


async def _auth(c, email, password) -> dict:
    r = await c.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


async def _enroll(c, op_auth) -> str:
    cl = (await c.post("/clients", json={"name": f"MC Clinic {uuid4().hex}"}, headers=op_auth)).json()
    st = (await c.post("/sites", json={"client_id": cl["id"], "name": "HQ"}, headers=op_auth)).json()
    et = (await c.post("/enrollment-tokens", json={"site_id": st["id"], "max_uses": 5}, headers=op_auth)).json()
    r = await c.post("/enroll", json={
        "enrollment_token": et["token"],
        "hostname": "PC-MESH",
        "os": "windows",
        "supported_command_envelope_versions": [COMMAND_ENVELOPE_V2],
        "supported_capabilities": [],
    })
    assert r.status_code == 200, r.text
    async with AsyncSessionLocal() as db:
        await grant_all_memberships(db)
        await db.commit()
    return r.json()["agent_id"]


async def _map(agent_id, *, node_id="node//abc", state=MeshMappingState.active,
               last_synced_delta=timedelta(minutes=1)):
    async with AsyncSessionLocal() as db:
        db.add(AgentMeshMapping(
            agent_id=agent_id,
            meshcentral_node_id=node_id,
            state=state,
            origin=MeshMappingOrigin.manual,
            created_by="mc-op@nodelink.test",
            last_synced_at=_now() - last_synced_delta,
            created_at=_now(),
            updated_at=_now(),
        ))
        await db.commit()


async def _set_trust(agent_id, state: AgentTrustState):
    async with AsyncSessionLocal() as db:
        agent = await db.get(Agent, agent_id)
        agent.trust_state = state
        await db.commit()


async def _actions() -> list[str]:
    async with AsyncSessionLocal() as db:
        return list((await db.execute(select(AuditEvent.action).order_by(AuditEvent.ts))).scalars())


async def _launch(c, auth, agent_id, **body):
    return await c.post(f"/agents/{agent_id}/remote-desktop/launches", json=body, headers=auth)


# --------------------------------------------------------------------------- #
# Authorization + provider gate
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_provider_disabled_fails_closed(env, monkeypatch):
    c, _ = env
    op = await _auth(c, "mc-op@nodelink.test", "op-pass")
    agent_id = await _enroll(c, op)
    await _map(agent_id)
    monkeypatch.setattr(settings, "meshcentral_provider", "disabled")
    r = await _launch(c, op, agent_id)
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "remote_desktop_disabled"
    assert "meshcentral.launch_denied" in await _actions()


@pytest.mark.asyncio
async def test_readonly_cannot_launch(env):
    c, _ = env
    op = await _auth(c, "mc-op@nodelink.test", "op-pass")
    agent_id = await _enroll(c, op)
    await _map(agent_id)
    viewer = await _auth(c, "mc-viewer@nodelink.test", "viewer-pass")
    r = await _launch(c, viewer, agent_id)
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_operator_without_scope_denied(env):
    c, _ = env
    op = await _auth(c, "mc-op@nodelink.test", "op-pass")
    agent_id = await _enroll(c, op)
    await _map(agent_id)
    noscope = await _auth(c, "mc-noscope@nodelink.test", "noscope-pass")
    r = await _launch(c, noscope, agent_id)
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "remote_desktop_not_authorized"
    assert "meshcentral.launch_denied" in await _actions()


# --------------------------------------------------------------------------- #
# Agent + mapping gates
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_untrusted_agent_denied(env):
    c, _ = env
    op = await _auth(c, "mc-op@nodelink.test", "op-pass")
    agent_id = await _enroll(c, op)
    await _map(agent_id)
    await _set_trust(agent_id, AgentTrustState.quarantined)
    r = await _launch(c, op, agent_id)
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "agent_not_trusted"


@pytest.mark.asyncio
async def test_missing_mapping_unmapped(env):
    c, _ = env
    op = await _auth(c, "mc-op@nodelink.test", "op-pass")
    agent_id = await _enroll(c, op)
    r = await _launch(c, op, agent_id)
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "remote_desktop_unmapped"


@pytest.mark.asyncio
async def test_stale_mapping_refused(env):
    c, _ = env
    op = await _auth(c, "mc-op@nodelink.test", "op-pass")
    agent_id = await _enroll(c, op)
    # last_synced far beyond the staleness window
    await _map(agent_id, last_synced_delta=timedelta(days=3))
    r = await _launch(c, op, agent_id)
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "remote_desktop_mapping_stale"


@pytest.mark.asyncio
async def test_conflict_mapping_refused(env):
    c, _ = env
    op = await _auth(c, "mc-op@nodelink.test", "op-pass")
    agent_id = await _enroll(c, op)
    await _map(agent_id, state=MeshMappingState.conflict)
    r = await _launch(c, op, agent_id)
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "remote_desktop_mapping_conflict"


# --------------------------------------------------------------------------- #
# Success + evidence
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_successful_launch_mints_once_and_audits(env):
    c, fake = env
    op = await _auth(c, "mc-op@nodelink.test", "op-pass")
    agent_id = await _enroll(c, op)
    await _map(agent_id)
    r = await _launch(c, op, agent_id, reason="patch window")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "authorized"
    assert body["login_url"] and body["login_url"].startswith("https://")
    assert body["login_expires_at"] is not None
    assert body["meshcentral_node_id"] == "node//abc"
    assert len(fake.minted) == 1

    actions = await _actions()
    assert "meshcentral.launch_requested" in actions
    assert "meshcentral.session_launched" in actions
    # The minted login URL must never enter the audit chain.
    async with AsyncSessionLocal() as db:
        details = (await db.execute(select(AuditEvent.detail))).scalars().all()
    assert not any("login_url" in d for d in details)
    assert not any(fake.minted[0].login_url in str(d) for d in details)


@pytest.mark.asyncio
async def test_get_launch_never_returns_login_url_and_owner_isolated(env):
    c, _ = env
    op = await _auth(c, "mc-op@nodelink.test", "op-pass")
    agent_id = await _enroll(c, op)
    await _map(agent_id)
    launch = (await _launch(c, op, agent_id)).json()

    got = await c.get(
        f"/agents/{agent_id}/remote-desktop/launches/{launch['id']}", headers=op
    )
    assert got.status_code == 200
    assert got.json()["login_url"] is None

    # A different operator gets 404 (ID oracle protection), not 403.
    other = await _auth(c, "mc-op2@nodelink.test", "op2-pass")
    denied = await c.get(
        f"/agents/{agent_id}/remote-desktop/launches/{launch['id']}", headers=other
    )
    assert denied.status_code == 404


@pytest.mark.asyncio
async def test_meshcentral_unavailable_fails_closed(env):
    c, fake = env
    fake.available = False
    op = await _auth(c, "mc-op@nodelink.test", "op-pass")
    agent_id = await _enroll(c, op)
    await _map(agent_id)
    r = await _launch(c, op, agent_id)
    assert r.status_code == 503
    assert r.json()["detail"]["code"] == "remote_desktop_unavailable"
    assert "meshcentral.launch_failed" in await _actions()


@pytest.mark.asyncio
async def test_rate_limit_per_operator(env, monkeypatch):
    c, _ = env
    monkeypatch.setattr(settings, "meshcentral_max_launches_per_operator_per_minute", 2)
    op = await _auth(c, "mc-op@nodelink.test", "op-pass")
    agent_id = await _enroll(c, op)
    await _map(agent_id)
    assert (await _launch(c, op, agent_id)).status_code == 201
    assert (await _launch(c, op, agent_id)).status_code == 201
    third = await _launch(c, op, agent_id)
    assert third.status_code == 429
    assert third.json()["detail"]["code"] == "remote_desktop_rate_limited"


@pytest.mark.asyncio
async def test_close_is_idempotent_and_best_effort_revokes(env):
    c, fake = env
    op = await _auth(c, "mc-op@nodelink.test", "op-pass")
    agent_id = await _enroll(c, op)
    await _map(agent_id)
    launch = (await _launch(c, op, agent_id)).json()
    ref = fake.minted[0].session_ref

    first = await c.post(
        f"/agents/{agent_id}/remote-desktop/launches/{launch['id']}/close",
        json={}, headers=op,
    )
    assert first.status_code == 200
    assert first.json()["status"] == "closed"
    assert ref in fake.revoked
    assert "meshcentral.session_closed" in await _actions()

    # Idempotent: a second close returns the terminal record unchanged.
    second = await c.post(
        f"/agents/{agent_id}/remote-desktop/launches/{launch['id']}/close",
        json={}, headers=op,
    )
    assert second.status_code == 200
    assert second.json()["status"] == "closed"


@pytest.mark.asyncio
async def test_availability_reflects_states(env, monkeypatch):
    c, _ = env
    op = await _auth(c, "mc-op@nodelink.test", "op-pass")
    agent_id = await _enroll(c, op)

    # No mapping yet.
    a1 = await c.get(f"/agents/{agent_id}/remote-desktop/availability", headers=op)
    assert a1.json() == {"available": False, "reason": "no_mapping", "provider_enabled": True}

    await _map(agent_id)
    a2 = await c.get(f"/agents/{agent_id}/remote-desktop/availability", headers=op)
    assert a2.json()["available"] is True
    assert a2.json()["reason"] == "available"

    monkeypatch.setattr(settings, "meshcentral_provider", "disabled")
    a3 = await c.get(f"/agents/{agent_id}/remote-desktop/availability", headers=op)
    assert a3.json() == {"available": False, "reason": "provider_disabled", "provider_enabled": False}
