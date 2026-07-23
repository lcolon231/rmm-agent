# SPDX-License-Identifier: AGPL-3.0-only
"""Arbitrary-script execution authorization tests (issue #111).

Behavior under test:
  - dispatching powershell/shell requires the explicit per-operator
    can_execute_scripts grant; role alone (even admin) is insufficient
  - a typed kind (collect_inventory) is authorized by operator role without the
    grant
  - an unauthorized dispatch is rejected 403 BEFORE any command is signed or
    queued (no Command row is created)
  - allowed and denied decisions are audited without recording the script body
  - the admin grant endpoint flips the permission (audited) and a freshly
    granted operator can then dispatch

Run just this file:  pytest tests/test_script_authz.py -q
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_script_authz.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

from app.main import app  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V2  # noqa: E402
from app.models.models import (  # noqa: E402
    AuditEvent,
    Command,
    Operator,
    OperatorRole,
)

SCRIPT = "Get-Process | Stop-Process  # sentinel-script-body"


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add(Operator(  # operator role, NO script grant (default-deny)
            email="op@nodelink.test", password_hash=hash_password("pw"),
            role=OperatorRole.operator,
        ))
        db.add(Operator(  # operator role WITH the grant
            email="granted@nodelink.test", password_hash=hash_password("pw"),
            role=OperatorRole.operator, can_execute_scripts=True,
        ))
        db.add(Operator(  # admin role, NO grant — role must not imply scripts
            email="admin@nodelink.test", password_hash=hash_password("pw"),
            role=OperatorRole.admin,
        ))
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        yield c
    await engine.dispose()


async def _login(c, email):
    r = await c.post("/auth/login", json={"email": email, "password": "pw"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


async def _enroll(c, auth) -> str:
    cl = (await c.post("/clients", json={"name": "C"}, headers=auth)).json()
    st = (await c.post("/sites", json={"client_id": cl["id"], "name": "S"}, headers=auth)).json()
    et = (await c.post("/enrollment-tokens", json={"site_id": st["id"], "max_uses": 9}, headers=auth)).json()
    enr = (await c.post("/enroll", json={
        "enrollment_token": et["token"], "hostname": "H", "os": "windows",
        "supported_command_envelope_versions": [COMMAND_ENVELOPE_V2],
    })).json()
    return enr["agent_id"]


async def _dispatch(c, agent_id, auth, kind="powershell"):
    return await c.post(
        f"/agents/{agent_id}/commands",
        json={"kind": kind, "payload": {"script": SCRIPT}},
        headers=auth,
    )


async def _count(model) -> int:
    async with AsyncSessionLocal() as db:
        return (await db.execute(select(func.count()).select_from(model))).scalar_one()


@pytest.mark.asyncio
async def test_operator_without_grant_is_denied(client):
    admin_auth = await _login(client, "admin@nodelink.test")
    agent_id = await _enroll(client, admin_auth)

    op_auth = await _login(client, "op@nodelink.test")
    before = await _count(Command)
    r = await _dispatch(client, agent_id, op_auth)
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "script_execution_not_authorized"
    # Rejected before signing/queueing: no Command row was created.
    assert await _count(Command) == before


@pytest.mark.asyncio
async def test_admin_role_does_not_imply_script_permission(client):
    admin_auth = await _login(client, "admin@nodelink.test")
    agent_id = await _enroll(client, admin_auth)
    r = await _dispatch(client, agent_id, admin_auth)
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_granted_operator_may_dispatch(client):
    admin_auth = await _login(client, "admin@nodelink.test")
    agent_id = await _enroll(client, admin_auth)
    granted_auth = await _login(client, "granted@nodelink.test")
    for kind in ("powershell", "shell"):
        r = await _dispatch(client, agent_id, granted_auth, kind=kind)
        assert r.status_code == 200, (kind, r.text)


@pytest.mark.asyncio
async def test_typed_kind_allowed_by_role_without_grant(client):
    admin_auth = await _login(client, "admin@nodelink.test")
    agent_id = await _enroll(client, admin_auth)
    op_auth = await _login(client, "op@nodelink.test")
    r = await c_dispatch_inventory(client, agent_id, op_auth)
    assert r.status_code == 200, r.text


async def c_dispatch_inventory(c, agent_id, auth):
    return await c.post(
        f"/agents/{agent_id}/commands",
        json={"kind": "collect_inventory", "payload": {"script": "inv"}},
        headers=auth,
    )


@pytest.mark.asyncio
async def test_denial_is_audited_without_script_body(client):
    admin_auth = await _login(client, "admin@nodelink.test")
    agent_id = await _enroll(client, admin_auth)
    op_auth = await _login(client, "op@nodelink.test")
    await _dispatch(client, agent_id, op_auth)

    async with AsyncSessionLocal() as db:
        rows = (await db.execute(
            select(AuditEvent).where(AuditEvent.action == "command.dispatch_denied")
        )).scalars().all()
    assert len(rows) == 1
    ev = rows[0]
    assert ev.actor == "op@nodelink.test"
    assert ev.detail["kind"] == "powershell"
    assert ev.detail["reason"] == "arbitrary_script_execution_not_authorized"
    # The script body must never be in the audit record.
    assert "sentinel-script-body" not in str(ev.detail)


@pytest.mark.asyncio
async def test_admin_grant_endpoint_enables_dispatch(client):
    admin_auth = await _login(client, "admin@nodelink.test")
    agent_id = await _enroll(client, admin_auth)

    # Resolve the ungranted operator's id.
    async with AsyncSessionLocal() as db:
        op = (await db.execute(
            select(Operator).where(Operator.email == "op@nodelink.test")
        )).scalar_one()
    op_id = op.id

    # Denied before the grant.
    op_auth = await _login(client, "op@nodelink.test")
    assert (await _dispatch(client, agent_id, op_auth)).status_code == 403

    # Admin grants the permission (mandatory reason).
    r = await client.patch(
        f"/auth/operators/{op_id}/script-permission",
        json={"can_execute_scripts": True, "reason": "pilot runbook approval"},
        headers=admin_auth,
    )
    assert r.status_code == 200
    assert r.json()["can_execute_scripts"] is True

    # A fresh token now dispatches successfully.
    op_auth2 = await _login(client, "op@nodelink.test")
    assert (await _dispatch(client, agent_id, op_auth2)).status_code == 200

    # The grant transition is audited with actor + reason.
    async with AsyncSessionLocal() as db:
        ev = (await db.execute(
            select(AuditEvent).where(
                AuditEvent.action == "operator.script_permission_changed"
            )
        )).scalars().one()
    assert ev.actor == "admin@nodelink.test"
    assert ev.detail["granted"] is True
    assert ev.detail["reason"] == "pilot runbook approval"


@pytest.mark.asyncio
async def test_grant_endpoint_requires_admin(client):
    op_auth = await _login(client, "op@nodelink.test")
    async with AsyncSessionLocal() as db:
        op = (await db.execute(
            select(Operator).where(Operator.email == "op@nodelink.test")
        )).scalar_one()
    r = await client.patch(
        f"/auth/operators/{op.id}/script-permission",
        json={"can_execute_scripts": True, "reason": "x"},
        headers=op_auth,
    )
    assert r.status_code == 403
