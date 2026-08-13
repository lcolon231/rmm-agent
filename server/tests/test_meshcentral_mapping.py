# SPDX-License-Identifier: AGPL-3.0-only
"""MeshCentral identity mapping + reconciliation tests (issue #62).

Behavior under test:
  - reconcile_mappings ages a mapping to unmapped when its node disappears and
    to conflict when two agents claim one node; refreshes freshness otherwise
  - reconciliation NEVER creates mappings and NEVER promotes to active on the
    strength of an unavailable MeshCentral (fail closed)
  - admin manual-mapping CRUD is authorized (admin-only) and audited
  - permission sync: authorization is re-derived at launch time, so revoking an
    operator's scope after a mapping exists fails the launch closed

Run just this file:  pytest tests/test_meshcentral_mapping.py -q
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_meshcentral_mapping.db")
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
from app.core.config import settings  # noqa: E402
from app.core import meshcentral as mc  # noqa: E402
from app.core import meshcentral_mapping as mm  # noqa: E402
from app.api.meshcentral import get_meshcentral_client  # noqa: E402
from app.models.models import (  # noqa: E402
    AgentMeshMapping,
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
            email="mm-admin@nodelink.test",
            password_hash=hash_password("admin-pass"),
            role=OperatorRole.admin,
            script_execution_scope=ScriptExecutionScope.global_,
        ))
        db.add(Operator(
            email="mm-op@nodelink.test",
            password_hash=hash_password("op-pass"),
            role=OperatorRole.operator,
            script_execution_scope=ScriptExecutionScope.global_,
        ))
        await db.commit()
    monkeypatch.setattr(settings, "meshcentral_provider", "enabled")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        yield c
    app.dependency_overrides.pop(get_meshcentral_client, None)
    await engine.dispose()


async def _auth(c, email, password) -> dict:
    r = await c.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


async def _enroll(c, op_auth, host="PC-MAP") -> str:
    cl = (await c.post("/clients", json={"name": f"MM Clinic {uuid4().hex}"}, headers=op_auth)).json()
    st = (await c.post("/sites", json={"client_id": cl["id"], "name": "HQ"}, headers=op_auth)).json()
    et = (await c.post("/enrollment-tokens", json={"site_id": st["id"], "max_uses": 5}, headers=op_auth)).json()
    r = await c.post("/enroll", json={
        "enrollment_token": et["token"],
        "hostname": host,
        "os": "windows",
        "supported_command_envelope_versions": [COMMAND_ENVELOPE_V2],
        "supported_capabilities": [],
    })
    assert r.status_code == 200, r.text
    return r.json()["agent_id"]


async def _insert_mapping(agent_id, node_id, state=MeshMappingState.active, synced_delta=timedelta(minutes=1)):
    async with AsyncSessionLocal() as db:
        db.add(AgentMeshMapping(
            agent_id=agent_id,
            meshcentral_node_id=node_id,
            state=state,
            origin=MeshMappingOrigin.manual,
            last_synced_at=_now() - synced_delta,
            created_at=_now(),
            updated_at=_now(),
        ))
        await db.commit()


# --------------------------------------------------------------------------- #
# Reconciliation core
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_reconcile_marks_unmapped_when_node_absent(env):
    c = env
    admin = await _auth(c, "mm-admin@nodelink.test", "admin-pass")
    agent_id = await _enroll(c, admin)
    await _insert_mapping(agent_id, "node//gone")

    fake = mc.FakeMeshCentralClient(devices=[mc.MeshDevice(node_id="node//other")])
    async with AsyncSessionLocal() as db:
        run = await mm.reconcile_mappings(db, fake, settings)
        await db.commit()
    assert run.unmapped == 1
    async with AsyncSessionLocal() as db:
        row = await db.scalar(select(AgentMeshMapping))
    assert row.state == MeshMappingState.unmapped


@pytest.mark.asyncio
async def test_reconcile_marks_conflict_when_two_agents_share_node(env):
    c = env
    admin = await _auth(c, "mm-admin@nodelink.test", "admin-pass")
    a1 = await _enroll(c, admin, host="PC-1")
    a2 = await _enroll(c, admin, host="PC-2")
    await _insert_mapping(a1, "node//dup")
    await _insert_mapping(a2, "node//dup")

    fake = mc.FakeMeshCentralClient(devices=[mc.MeshDevice(node_id="node//dup")])
    async with AsyncSessionLocal() as db:
        run = await mm.reconcile_mappings(db, fake, settings)
        await db.commit()
    assert run.conflict == 2
    async with AsyncSessionLocal() as db:
        states = (await db.execute(select(AgentMeshMapping.state))).scalars().all()
    assert all(s == MeshMappingState.conflict for s in states)


@pytest.mark.asyncio
async def test_reconcile_refreshes_present_node(env):
    c = env
    admin = await _auth(c, "mm-admin@nodelink.test", "admin-pass")
    agent_id = await _enroll(c, admin)
    await _insert_mapping(agent_id, "node//live", synced_delta=timedelta(days=5))

    seen = _now()
    fake = mc.FakeMeshCentralClient(
        devices=[mc.MeshDevice(node_id="node//live", last_connect=seen)]
    )
    async with AsyncSessionLocal() as db:
        run = await mm.reconcile_mappings(db, fake, settings)
        await db.commit()
    assert run.active == 1
    async with AsyncSessionLocal() as db:
        row = await db.scalar(select(AgentMeshMapping))
    assert row.state == MeshMappingState.active
    assert row.last_synced_at is not None
    # Freshness moved forward past the staleness window.
    assert not mm.is_stale(row, settings, _now())


@pytest.mark.asyncio
async def test_reconcile_leaves_mappings_when_meshcentral_unavailable(env):
    c = env
    admin = await _auth(c, "mm-admin@nodelink.test", "admin-pass")
    agent_id = await _enroll(c, admin)
    await _insert_mapping(agent_id, "node//x", state=MeshMappingState.unmapped)

    fake = mc.FakeMeshCentralClient(available=False)
    async with AsyncSessionLocal() as db:
        run = await mm.reconcile_mappings(db, fake, settings)
        await db.commit()
    assert run.unavailable is True
    async with AsyncSessionLocal() as db:
        row = await db.scalar(select(AgentMeshMapping))
    # Not promoted to active on a failed sync.
    assert row.state == MeshMappingState.unmapped


# --------------------------------------------------------------------------- #
# Admin CRUD
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_admin_create_list_delete_mapping(env):
    c = env
    admin = await _auth(c, "mm-admin@nodelink.test", "admin-pass")
    agent_id = await _enroll(c, admin)

    created = await c.post("/remote-desktop/mappings", headers=admin, json={
        "agent_id": agent_id, "meshcentral_node_id": "node//abc", "meshcentral_mesh_id": "mesh//1",
    })
    assert created.status_code == 201, created.text
    mapping_id = created.json()["id"]
    assert created.json()["origin"] == "manual"

    # Duplicate is refused.
    dup = await c.post("/remote-desktop/mappings", headers=admin, json={
        "agent_id": agent_id, "meshcentral_node_id": "node//zzz",
    })
    assert dup.status_code == 409

    listing = await c.get("/remote-desktop/mappings", headers=admin)
    assert listing.status_code == 200
    assert any(m["id"] == mapping_id for m in listing.json())

    deleted = await c.delete(f"/remote-desktop/mappings/{mapping_id}", headers=admin)
    assert deleted.status_code == 204

    async with AsyncSessionLocal() as db:
        actions = (await db.execute(select(AuditEvent.action))).scalars().all()
    assert "meshcentral.mapping_created" in actions
    assert "meshcentral.mapping_deleted" in actions


@pytest.mark.asyncio
async def test_operator_cannot_manage_mappings(env):
    c = env
    admin = await _auth(c, "mm-admin@nodelink.test", "admin-pass")
    agent_id = await _enroll(c, admin)
    op = await _auth(c, "mm-op@nodelink.test", "op-pass")
    r = await c.post("/remote-desktop/mappings", headers=op, json={
        "agent_id": agent_id, "meshcentral_node_id": "node//abc",
    })
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_admin_sync_endpoint_audits(env, monkeypatch):
    c = env
    admin = await _auth(c, "mm-admin@nodelink.test", "admin-pass")
    agent_id = await _enroll(c, admin)
    await _insert_mapping(agent_id, "node//gone")

    fake = mc.FakeMeshCentralClient(devices=[mc.MeshDevice(node_id="node//other")])
    monkeypatch.setattr(mc, "get_client", lambda cfg=settings: fake)

    r = await c.post("/remote-desktop/mappings/sync", headers=admin)
    assert r.status_code == 200, r.text
    assert r.json()["unmapped"] == 1
    async with AsyncSessionLocal() as db:
        actions = (await db.execute(select(AuditEvent.action))).scalars().all()
    assert "meshcentral.mapping_synced" in actions
    assert "meshcentral.mapping_stale" in actions


@pytest.mark.asyncio
async def test_provider_status_reports_counts(env):
    c = env
    admin = await _auth(c, "mm-admin@nodelink.test", "admin-pass")
    agent_id = await _enroll(c, admin)
    await _insert_mapping(agent_id, "node//abc", synced_delta=timedelta(days=3))
    r = await c.get("/remote-desktop/provider", headers=admin)
    assert r.status_code == 200
    body = r.json()
    assert body["provider"] == "enabled"
    assert body["mapping_count"] == 1
    assert body["stale_mapping_count"] == 1


# --------------------------------------------------------------------------- #
# Permission sync (authorization re-derived at launch)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_authorization_revoked_after_mapping_fails_closed(env):
    c = env
    admin = await _auth(c, "mm-admin@nodelink.test", "admin-pass")
    op = await _auth(c, "mm-op@nodelink.test", "op-pass")
    agent_id = await _enroll(c, admin)
    await _insert_mapping(agent_id, "node//abc")

    fake = mc.FakeMeshCentralClient()
    app.dependency_overrides[get_meshcentral_client] = lambda: fake

    # With scope, the operator can launch.
    ok = await c.post(f"/agents/{agent_id}/remote-desktop/launches", headers=op, json={})
    assert ok.status_code == 201

    # Revoke the operator's arbitrary-script scope; the very next launch fails
    # closed because authorization is re-derived at mint time.
    async with AsyncSessionLocal() as db:
        row = await db.scalar(select(Operator).where(Operator.email == "mm-op@nodelink.test"))
        row.script_execution_scope = None
        await db.commit()
    denied = await c.post(f"/agents/{agent_id}/remote-desktop/launches", headers=op, json={})
    assert denied.status_code == 403
    assert denied.json()["detail"]["code"] == "remote_desktop_not_authorized"
