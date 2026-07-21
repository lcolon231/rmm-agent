"""Auth tests — written BEFORE the implementation (TDD).

These describe the behavior we want:
  - login rejects bad credentials identically (no account enumeration)
  - login returns a usable token
  - the management API refuses unauthenticated callers
  - roles are enforced: read-only can look but not dispatch
  - the acting operator's identity lands in the audit log

Run just this file:  pytest tests/test_auth.py -q
"""
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_auth.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402

from app.main import app  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.models.models import Operator, OperatorRole  # noqa: E402


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    # Seed two operators: one who can dispatch, one read-only.
    async with AsyncSessionLocal() as db:
        db.add(
            Operator(
                email="admin@nodelink.test",
                password_hash=hash_password("correct-horse"),
                role=OperatorRole.operator,
            )
        )
        db.add(
            Operator(
                email="viewer@nodelink.test",
                password_hash=hash_password("read-only-pass"),
                role=OperatorRole.readonly,
            )
        )
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        yield c
    await engine.dispose()


async def _login(c, email, password):
    return await c.post("/api/v1/auth/login", json={"email": email, "password": password})


@pytest.mark.asyncio
async def test_wrong_password_and_unknown_user_look_identical(client):
    r_wrong = await _login(client, "admin@nodelink.test", "nope")
    r_missing = await _login(client, "ghost@nodelink.test", "whatever")
    assert r_wrong.status_code == 401
    assert r_missing.status_code == 401
    # Same body — no way to tell which accounts exist.
    assert r_wrong.json() == r_missing.json()


@pytest.mark.asyncio
async def test_login_success_returns_token(client):
    r = await _login(client, "admin@nodelink.test", "correct-horse")
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]


@pytest.mark.asyncio
async def test_management_requires_auth(client):
    # No Authorization header -> refused.
    r = await client.get("/api/v1/agents")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_client_navigation_requires_auth(client):
    assert (await client.get("/api/v1/clients/navigation")).status_code == 401
    assert (await client.get("/api/v1/clients/missing")).status_code == 401
    assert (await client.get("/api/v1/sites/missing")).status_code == 401
    assert (await client.get("/api/v1/endpoints")).status_code == 401


@pytest.mark.asyncio
async def test_endpoint_list_validates_filters_and_is_readonly(client):
    token = (await _login(client, "admin@nodelink.test", "correct-horse")).json()["access_token"]
    auth = {"Authorization": f"Bearer {token}"}
    assert (await client.get("/api/v1/endpoints?page=0", headers=auth)).status_code == 422
    assert (await client.get("/api/v1/endpoints?page_size=101", headers=auth)).status_code == 422
    response = await client.get("/api/v1/endpoints?sort=hostname&direction=asc&page=1&page_size=25", headers=auth)
    assert response.status_code == 200
    assert response.json() == {"items": [], "page": 1, "page_size": 25, "total": 0}


@pytest.mark.asyncio
async def test_readonly_client_navigation_lists_details_and_audits(client):
    operator_token = (await _login(client, "admin@nodelink.test", "correct-horse")).json()["access_token"]
    operator_auth = {"Authorization": f"Bearer {operator_token}"}
    client_out = (await client.post("/api/v1/clients", json={"name": "Navigation Clinic"}, headers=operator_auth)).json()
    site_out = (
        await client.post(
            "/api/v1/sites",
            json={"client_id": client_out["id"], "name": "HQ"},
            headers=operator_auth,
        )
    ).json()
    readonly_token = (await _login(client, "viewer@nodelink.test", "read-only-pass")).json()["access_token"]
    readonly_auth = {"Authorization": f"Bearer {readonly_token}"}

    navigation = await client.get("/api/v1/clients/navigation", headers=readonly_auth)
    assert navigation.status_code == 200
    assert navigation.json() == {
        "items": [{"id": client_out["id"], "name": "Navigation Clinic", "sites": [{"id": site_out["id"], "client_id": client_out["id"], "name": "HQ", "endpoint_count": 0}]}],
        "truncated": False,
    }
    assert (await client.get(f"/api/v1/clients/{client_out['id']}", headers=readonly_auth)).status_code == 200
    assert (await client.get(f"/api/v1/sites/{site_out['id']}", headers=readonly_auth)).status_code == 200
    assert (await client.get("/api/v1/clients/missing", headers=readonly_auth)).status_code == 404

    from sqlalchemy import select
    from app.models.models import AuditEvent

    async with AsyncSessionLocal() as db:
        events = (await db.execute(select(AuditEvent.action, AuditEvent.actor))).all()
    assert ("client_navigation.list_viewed", "viewer@nodelink.test") in events
    assert ("client_navigation.client_viewed", "viewer@nodelink.test") in events
    assert ("client_navigation.site_viewed", "viewer@nodelink.test") in events


@pytest.mark.asyncio
async def test_readonly_can_read_but_not_dispatch(client):
    # An operator-role user does the provisioning (read-only can't).
    op_tok = (await _login(client, "admin@nodelink.test", "correct-horse")).json()["access_token"]
    op_auth = {"Authorization": f"Bearer {op_tok}"}
    cl = (await client.post("/api/v1/clients", json={"name": "C"}, headers=op_auth)).json()
    st = (await client.post("/api/v1/sites", json={"client_id": cl["id"], "name": "S"}, headers=op_auth)).json()
    et = (await client.post("/api/v1/enrollment-tokens", json={"site_id": st["id"]}, headers=op_auth)).json()
    enr = (
        await client.post(
            "/api/v1/enroll",
            json={"enrollment_token": et["token"], "hostname": "H", "os": "windows", "supported_command_envelope_versions": ["command-v2"]},
        )
    ).json()

    # Now act as the read-only operator.
    ro_tok = (await _login(client, "viewer@nodelink.test", "read-only-pass")).json()["access_token"]
    ro_auth = {"Authorization": f"Bearer {ro_tok}"}

    # Reading is allowed.
    assert (await client.get("/api/v1/agents", headers=ro_auth)).status_code == 200

    # Provisioning is NOT allowed for read-only.
    assert (
        await client.post("/api/v1/clients", json={"name": "X"}, headers=ro_auth)
    ).status_code == 403

    # Dispatching is NOT allowed for read-only.
    r = await client.post(
        f"/api/v1/agents/{enr['agent_id']}/commands",
        json={"kind": "shell", "payload": {"script": "echo x"}},
        headers=ro_auth,
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_dispatch_records_operator_identity(client):
    tok = (await _login(client, "admin@nodelink.test", "correct-horse")).json()["access_token"]
    auth = {"Authorization": f"Bearer {tok}"}

    cl = (await client.post("/api/v1/clients", json={"name": "C"}, headers=auth)).json()
    st = (await client.post("/api/v1/sites", json={"client_id": cl["id"], "name": "S"}, headers=auth)).json()
    et = (await client.post("/api/v1/enrollment-tokens", json={"site_id": st["id"]}, headers=auth)).json()
    enr = (
        await client.post(
            "/api/v1/enroll",
            json={"enrollment_token": et["token"], "hostname": "H", "os": "windows", "supported_command_envelope_versions": ["command-v2"]},
        )
    ).json()

    r = await client.post(
        f"/api/v1/agents/{enr['agent_id']}/commands",
        json={"kind": "shell", "payload": {"script": "echo x"}},
        headers=auth,
    )
    assert r.status_code == 200

    # The audit event should name the operator, not a hardcoded "operator".
    from sqlalchemy import select
    from app.models.models import AuditEvent

    async with AsyncSessionLocal() as db:
        rows = (
            await db.execute(
                select(AuditEvent).where(AuditEvent.action == "command.dispatched")
            )
        ).scalars().all()
    assert len(rows) == 1
    assert rows[0].actor == "admin@nodelink.test"
    assert rows[0].detail["payload_keys"] == ["script"]
    assert "payload" not in rows[0].detail
    assert len(rows[0].detail["envelope_sha256"]) == 64
