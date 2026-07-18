# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for token revocation and login rate-limiting.

Behavior under test:
  - once the failure window fills, login answers 429 (with Retry-After) even
    for the correct password — and other accounts are unaffected
  - a successful login clears the caller's failure counter
  - self revocation invalidates every outstanding token, including the one
    that made the call; a fresh login works
  - an admin can revoke another operator's tokens; a non-admin cannot
  - revocations land in the audit log

Run just this file:  pytest tests/test_revocation_ratelimit.py -q
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_revocation.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402

from app.main import app  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.ratelimit import login_limiter  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.models.models import Operator, OperatorRole  # noqa: E402


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add(
            Operator(
                email="rl-admin@nodelink.test",
                password_hash=hash_password("admin-pass"),
                role=OperatorRole.admin,
            )
        )
        db.add(
            Operator(
                email="rl-viewer@nodelink.test",
                password_hash=hash_password("viewer-pass"),
                role=OperatorRole.readonly,
            )
        )
        await db.commit()
    login_limiter.reset()  # isolate rate-limit state per test
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        yield c
    login_limiter.reset()
    await engine.dispose()


async def _login(c, email, password):
    return await c.post("/api/v1/auth/login", json={"email": email, "password": password})


async def _token(c, email, password) -> str:
    r = await _login(c, email, password)
    assert r.status_code == 200
    return r.json()["access_token"]


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_login_locks_after_repeated_failures(client):
    for _ in range(login_limiter.max_failures):
        assert (await _login(client, "rl-admin@nodelink.test", "wrong")).status_code == 401

    # Window is full: even the CORRECT password is refused with 429.
    r = await _login(client, "rl-admin@nodelink.test", "admin-pass")
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) >= 1


@pytest.mark.asyncio
async def test_rate_limit_is_per_email(client):
    for _ in range(login_limiter.max_failures):
        await _login(client, "rl-admin@nodelink.test", "wrong")

    # A different account from the same client is not locked out.
    assert (await _login(client, "rl-viewer@nodelink.test", "viewer-pass")).status_code == 200


@pytest.mark.asyncio
async def test_success_clears_failure_counter(client):
    # A couple of typos followed by a success must not leave a residue that
    # later locks the account.
    for _ in range(login_limiter.max_failures - 1):
        await _login(client, "rl-admin@nodelink.test", "wrong")
    assert (await _login(client, "rl-admin@nodelink.test", "admin-pass")).status_code == 200

    for _ in range(login_limiter.max_failures - 1):
        await _login(client, "rl-admin@nodelink.test", "wrong")
    assert (await _login(client, "rl-admin@nodelink.test", "admin-pass")).status_code == 200


# --------------------------------------------------------------------------- #
# Token revocation
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_self_revocation_invalidates_outstanding_tokens(client):
    tok = await _token(client, "rl-viewer@nodelink.test", "viewer-pass")
    auth = {"Authorization": f"Bearer {tok}"}
    assert (await client.get("/api/v1/auth/me", headers=auth)).status_code == 200

    r = await client.post("/api/v1/auth/revoke-tokens", headers=auth)
    assert r.status_code == 204

    # The very token that made the call is now dead.
    assert (await client.get("/api/v1/auth/me", headers=auth)).status_code == 401

    # A fresh login mints a working token under the new generation.
    tok2 = await _token(client, "rl-viewer@nodelink.test", "viewer-pass")
    assert (
        await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tok2}"})
    ).status_code == 200


@pytest.mark.asyncio
async def test_admin_can_revoke_another_operators_tokens(client):
    viewer_tok = await _token(client, "rl-viewer@nodelink.test", "viewer-pass")
    viewer_auth = {"Authorization": f"Bearer {viewer_tok}"}
    admin_tok = await _token(client, "rl-admin@nodelink.test", "admin-pass")
    admin_auth = {"Authorization": f"Bearer {admin_tok}"}

    viewer_id = (await client.get("/api/v1/auth/me", headers=viewer_auth)).json()["id"]

    r = await client.post(
        f"/api/v1/auth/operators/{viewer_id}/revoke-tokens", headers=admin_auth
    )
    assert r.status_code == 204

    # Viewer's old token is dead; the admin's own token still works.
    assert (await client.get("/api/v1/auth/me", headers=viewer_auth)).status_code == 401
    assert (await client.get("/api/v1/auth/me", headers=admin_auth)).status_code == 200


@pytest.mark.asyncio
async def test_non_admin_cannot_revoke_others(client):
    viewer_tok = await _token(client, "rl-viewer@nodelink.test", "viewer-pass")
    viewer_auth = {"Authorization": f"Bearer {viewer_tok}"}
    admin_tok = await _token(client, "rl-admin@nodelink.test", "admin-pass")

    admin_id = (
        await client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {admin_tok}"}
        )
    ).json()["id"]

    r = await client.post(
        f"/api/v1/auth/operators/{admin_id}/revoke-tokens", headers=viewer_auth
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_revocation_is_audited(client):
    tok = await _token(client, "rl-viewer@nodelink.test", "viewer-pass")
    await client.post(
        "/api/v1/auth/revoke-tokens", headers={"Authorization": f"Bearer {tok}"}
    )

    from sqlalchemy import select
    from app.models.models import AuditEvent

    async with AsyncSessionLocal() as db:
        rows = (
            await db.execute(
                select(AuditEvent).where(AuditEvent.action == "operator.tokens_revoked")
            )
        ).scalars().all()
    assert len(rows) == 1
    assert rows[0].actor == "rl-viewer@nodelink.test"
