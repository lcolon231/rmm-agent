"""Auth tests — written BEFORE the implementation (TDD).

These describe the behavior we want:
  - login rejects bad credentials identically (no account enumeration)
  - login returns a usable token
  - the management API refuses unauthenticated callers
  - roles are enforced: read-only can look but not dispatch
  - the acting operator's identity lands in the audit log

Run just this file:  pytest tests/test_auth.py -q
"""
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
            json={"enrollment_token": et["token"], "hostname": "H", "os": "windows"},
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
            json={"enrollment_token": et["token"], "hostname": "H", "os": "windows"},
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
