# SPDX-License-Identifier: AGPL-3.0-only
"""Refusal table for the shared authN/authZ dependencies in app/api/deps.py (#284).

Every operator- and agent-facing route resolves its caller through these
dependencies, so each refusal branch is driven here once, over HTTP, against a
representative route instead of being re-proven by every router's tests.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_auth_dependencies.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from jose import jwt  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import (  # noqa: E402
    create_access_token,
    create_mfa_pending_token,
    hash_password,
    hash_token,
)
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    AgentTrustState,
    Client,
    Operator,
    OperatorRole,
    Site,
)

OPERATOR_ID = "op-deps"
DISABLED_ID = "op-disabled"
AGENT_TOKEN = "agent-token-current"
OLD_AGENT_TOKEN = "agent-token-previous"

OPERATOR_ROUTE = "/clients"  # readonly route on the management router
ADMIN_ROUTE = "/auth/break-glass"  # require_platform_admin
MFA_ROUTE = "/auth/mfa/login/options"  # get_mfa_pending_operator
AGENT_ROUTE = "/agents/me/shell-sessions/attach"  # get_current_agent
REATTACH_ROUTE = "/agents/credentials/reattach"  # get_agent_for_credential_reattach


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                Operator(
                    id=OPERATOR_ID,
                    email="deps@nodelink.test",
                    password_hash=hash_password("deps-pass"),
                    role=OperatorRole.readonly,
                    token_generation=2,
                ),
                Operator(
                    id=DISABLED_ID,
                    email="disabled@nodelink.test",
                    password_hash=hash_password("disabled-pass"),
                    role=OperatorRole.admin,
                    disabled=True,
                ),
            ]
        )
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        yield c
    await engine.dispose()


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _expired_token() -> str:
    claims = {
        "sub": OPERATOR_ID,
        "gen": 2,
        "typ": "access",
        "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
    }
    return jwt.encode(claims, settings.secret_key, algorithm=settings.jwt_algorithm)


# (case id, headers factory, expected detail). Every row must yield 401.
OPERATOR_REFUSALS = [
    ("missing-header", lambda: {}, "Missing Authorization header"),
    ("wrong-scheme", lambda: {"Authorization": "Basic abc"}, "Missing or malformed Authorization header"),
    ("empty-bearer", lambda: {"Authorization": "Bearer "}, "Missing or malformed Authorization header"),
    ("bad-signature", lambda: _bearer("not.a.jwt"), "Invalid or expired token"),
    ("expired", lambda: _bearer(_expired_token()), "Invalid or expired token"),
    (
        "mfa-pending-type",
        lambda: _bearer(create_mfa_pending_token(OPERATOR_ID, 2)),
        "Invalid or expired token",
    ),
    (
        "unknown-operator",
        lambda: _bearer(create_access_token("nobody", 0)),
        "Operator not found or disabled",
    ),
    (
        "disabled-operator",
        lambda: _bearer(create_access_token(DISABLED_ID, 0)),
        "Operator not found or disabled",
    ),
    (
        "stale-generation",
        lambda: _bearer(create_access_token(OPERATOR_ID, 1)),
        "Invalid or expired token",
    ),
    (
        "unknown-session",
        lambda: _bearer(create_access_token(OPERATOR_ID, 2, session_id="gone")),
        "Invalid or expired token",
    ),
]


@pytest.mark.parametrize(
    ("headers", "detail"),
    [row[1:] for row in OPERATOR_REFUSALS],
    ids=[row[0] for row in OPERATOR_REFUSALS],
)
async def test_operator_authentication_refusals(client, headers, detail):
    refused = await client.get(OPERATOR_ROUTE, headers=headers())
    assert refused.status_code == 401
    assert refused.json()["detail"] == detail


async def test_legacy_token_without_session_follows_the_flag(client, monkeypatch):
    legacy = _bearer(create_access_token(OPERATOR_ID, 2))
    assert (await client.get(OPERATOR_ROUTE, headers=legacy)).status_code == 200
    monkeypatch.setattr(settings, "admin_session_accept_legacy_tokens", False)
    refused = await client.get(OPERATOR_ROUTE, headers=legacy)
    assert refused.status_code == 401
    assert refused.json()["detail"] == "Invalid or expired token"


async def test_role_and_platform_admin_gates(client):
    readonly = _bearer(create_access_token(OPERATOR_ID, 2))
    created = await client.post("/clients", json={"name": "Nope"}, headers=readonly)
    assert created.status_code == 403
    assert created.json()["detail"] == "Requires role 'operator' or higher"
    denied = await client.get(ADMIN_ROUTE, headers=readonly)
    assert denied.status_code == 403
    assert denied.json()["detail"] == "Requires platform administrator"


@pytest.mark.parametrize(
    "headers",
    [
        lambda: {},
        lambda: {"Authorization": "Token x"},
        lambda: _bearer(create_access_token(OPERATOR_ID, 2)),
    ],
    ids=["missing", "malformed", "full-access-token"],
)
async def test_mfa_completion_accepts_only_the_pending_token(client, headers):
    refused = await client.post(MFA_ROUTE, json={}, headers=headers())
    assert refused.status_code == 401


async def _seed_agent(**fields) -> None:
    now = datetime.now(timezone.utc)
    values = {
        "id": "agent-deps",
        "hostname": "PC-DEPS",
        "os": "windows",
        "site_id": "site-deps",
        "token_hash": hash_token(AGENT_TOKEN),
        "trust_state": AgentTrustState.active,
        "credential_expires_at": now + timedelta(days=1),
    }
    values.update(fields)
    async with AsyncSessionLocal() as db:
        db.add(Client(id="client-deps", name="Deps Clinic"))
        db.add(Site(id="site-deps", client_id="client-deps", name="HQ"))
        await db.flush()
        db.add(Agent(**values))
        await db.commit()


@pytest.mark.parametrize("route", [AGENT_ROUTE, REATTACH_ROUTE])
@pytest.mark.parametrize(
    "authorization",
    [None, "Basic abc", "Bearer ", "Bearer unknown-token"],
    ids=["missing", "wrong-scheme", "empty", "unknown"],
)
async def test_agent_header_refusals(client, route, authorization):
    await _seed_agent()
    headers = {} if authorization is None else {"Authorization": authorization}
    refused = await client.post(route, headers=headers)
    assert refused.status_code == 401


AGENT_STATE_REFUSALS = [
    ("revoked", {"trust_state": AgentTrustState.revoked}, AGENT_TOKEN),
    ("current-expired", {"credential_expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)}, AGENT_TOKEN),
    (
        "overlap-lapsed",
        {
            "previous_token_hash": hash_token(OLD_AGENT_TOKEN),
            "previous_token_expires_at": datetime.now(timezone.utc) - timedelta(seconds=1),
        },
        OLD_AGENT_TOKEN,
    ),
]


@pytest.mark.parametrize(
    ("fields", "token"),
    [row[1:] for row in AGENT_STATE_REFUSALS],
    ids=[row[0] for row in AGENT_STATE_REFUSALS],
)
async def test_agent_credential_state_refusals_share_one_opaque_401(client, fields, token):
    await _seed_agent(**fields)
    refused = await client.post(AGENT_ROUTE, headers=_bearer(token))
    assert refused.status_code == 401
    assert refused.json()["detail"] == "Invalid agent token"


async def test_reattach_refuses_a_credential_that_has_not_expired(client):
    # Reattachment is only for a lapsed bearer; a live one must use renewal.
    await _seed_agent()
    refused = await client.post(REATTACH_ROUTE, headers=_bearer(AGENT_TOKEN))
    assert refused.status_code == 401
    assert refused.json()["detail"] == "Invalid agent token"
