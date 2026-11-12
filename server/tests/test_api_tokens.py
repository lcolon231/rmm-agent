# SPDX-License-Identifier: AGPL-3.0-only
"""Tenant-scoped API tokens for the public v1 API (issue #72).

A token is an unattended bearer credential, so every test here is about a
boundary it must not cross: its one tenant, its role ceilings, the public
route allowlist, step-up and MFA-gated operations, its own lifetime and kill
switches, and its owner. Each refusal is checked for the exact status a
client can see (opaque 401 / anti-oracle 404 / 403), and the audit trail for
the evidence an operator relies on afterwards.
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_api_tokens.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")
_OWNER_PW = os.environ.setdefault("NODELINK_TEST_TOKEN_OWNER_PW", "owner-pw")
_OTHER_PW = os.environ.setdefault("NODELINK_TEST_TOKEN_OTHER_PW", "other-pw")
_PLATFORM_PW = os.environ.setdefault("NODELINK_TEST_TOKEN_PLATFORM_PW", "platform-pw")

from datetime import datetime, timedelta, timezone  # noqa: E402

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core import api_tokens, public_api  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V3  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    ApiToken,
    AuditEvent,
    Client,
    ClientRole,
    Command,
    Operator,
    OperatorClientMembership,
    OperatorRole,
    Site,
)

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def env():
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    api_tokens.request_limiter.reset()
    api_tokens.mutating_limiter.reset()

    async with AsyncSessionLocal() as db:
        owner = Operator(
            email="owner@nodelink.test", password_hash=hash_password(_OWNER_PW),
            role=OperatorRole.operator,
        )
        other = Operator(
            email="other@nodelink.test", password_hash=hash_password(_OTHER_PW),
            role=OperatorRole.operator,
        )
        platform = Operator(
            email="platform@nodelink.test", password_hash=hash_password(_PLATFORM_PW),
            role=OperatorRole.admin, is_platform_admin=True,
        )
        client_a = Client(name="Alpha")
        client_b = Client(name="Bravo")
        db.add_all([owner, other, platform, client_a, client_b])
        await db.flush()
        site_a = Site(client_id=client_a.id, name="A-HQ")
        site_b = Site(client_id=client_b.id, name="B-HQ")
        db.add_all([site_a, site_b])
        await db.flush()
        agent_a = Agent(
            site_id=site_a.id, token_hash="a-hash", hostname="A-1", os="windows",
            command_envelope_versions=[COMMAND_ENVELOPE_V3],
        )
        agent_b = Agent(
            site_id=site_b.id, token_hash="b-hash", hostname="B-1", os="windows",
            command_envelope_versions=[COMMAND_ENVELOPE_V3],
        )
        db.add_all([agent_a, agent_b])
        db.add_all([
            # owner: operator on A *and* B -- a token must still see only one.
            OperatorClientMembership(
                operator_id=owner.id, client_id=client_a.id,
                role=ClientRole.client_operator, granted_by="seed", reason="seed",
            ),
            OperatorClientMembership(
                operator_id=owner.id, client_id=client_b.id,
                role=ClientRole.client_operator, granted_by="seed", reason="seed",
            ),
            OperatorClientMembership(
                operator_id=other.id, client_id=client_a.id,
                role=ClientRole.client_admin, granted_by="seed", reason="seed",
            ),
        ])
        await db.commit()
        ids = {
            "owner": owner.id, "other": other.id, "platform": platform.id,
            "client_a": client_a.id, "client_b": client_b.id,
            "agent_a": agent_a.id, "agent_b": agent_b.id,
        }

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as http:
        async def login(email: str, password: str) -> dict:
            resp = await http.post("/auth/login", json={"email": email, "password": password})
            assert resp.status_code == 200, resp.text
            return {"Authorization": f"Bearer {resp.json()['access_token']}"}

        sessions = {
            "owner": await login("owner@nodelink.test", _OWNER_PW),
            "other": await login("other@nodelink.test", _OTHER_PW),
            "platform": await login("platform@nodelink.test", _PLATFORM_PW),
        }
        yield http, ids, sessions
    await engine.dispose()


async def _mint(http, session, client_id, **fields) -> dict:
    resp = await http.post(
        "/api-tokens",
        headers=session,
        json={"name": "ci-integration", "client_id": client_id, **fields},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _bearer(token: dict) -> dict:
    return {"Authorization": f"Bearer {token['token']}"}


async def test_mint_returns_secret_once_and_stores_only_its_hash(env):
    http, ids, sessions = env
    created = await _mint(http, sessions["owner"], ids["client_a"])
    assert created["token"].startswith("nlk_")
    assert created["prefix"] == created["token"][:10]
    assert created["role_ceiling"] == "readonly"
    assert created["client_role_ceiling"] == "client_readonly"
    expires = datetime.fromisoformat(created["expires_at"].replace("Z", "+00:00"))
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    assert timedelta(days=29) < expires - datetime.now(timezone.utc) <= timedelta(days=30)

    listed = (await http.get("/api-tokens", headers=sessions["owner"])).json()["items"]
    assert [t["id"] for t in listed] == [created["id"]]
    assert "token" not in listed[0]
    async with AsyncSessionLocal() as db:
        row = await db.get(ApiToken, created["id"])
        assert row.token_hash != created["token"] and len(row.token_hash) == 64
        events = (await db.execute(select(AuditEvent).where(AuditEvent.action == "api_token.created"))).scalars().all()
    [event] = events
    assert created["token"] not in str(event.detail)
    assert row.token_hash not in str(event.detail)
    assert "ci-integration" not in str(event.detail)  # name is digested
    assert event.detail["client_id"] == ids["client_a"]


async def test_token_reads_only_its_one_tenant(env):
    http, ids, sessions = env
    token = _bearer(await _mint(http, sessions["owner"], ids["client_a"]))

    assert (await http.get(f"/agents/{ids['agent_a']}", headers=token)).status_code == 200
    # The owner can see B with their session; the token bound to A cannot.
    assert (await http.get(f"/agents/{ids['agent_b']}", headers=sessions["owner"])).status_code == 200
    assert (await http.get(f"/agents/{ids['agent_b']}", headers=token)).status_code == 404
    assert (await http.get(f"/endpoints/{ids['agent_b']}", headers=token)).status_code == 404
    listed = (await http.get("/endpoints", headers=token)).json()
    assert [item["id"] for item in listed["items"]] == [ids["agent_a"]]
    assert listed["total"] == 1


async def test_platform_admin_token_is_still_confined_to_one_client(env):
    http, ids, sessions = env
    token = _bearer(await _mint(http, sessions["platform"], ids["client_b"]))
    listed = (await http.get("/endpoints", headers=token)).json()
    assert [item["id"] for item in listed["items"]] == [ids["agent_b"]]
    assert (await http.get(f"/agents/{ids['agent_a']}", headers=token)).status_code == 404


async def test_role_ceiling_caps_dispatch(env):
    http, ids, sessions = env
    readonly = _bearer(await _mint(http, sessions["owner"], ids["client_a"]))
    refused = await http.post(
        f"/agents/{ids['agent_a']}/commands",
        json={"kind": "scan_updates", "payload": {}},
        headers=readonly,
    )
    assert refused.status_code == 403, refused.text

    operator = _bearer(await _mint(
        http, sessions["owner"], ids["client_a"],
        role_ceiling="operator", client_role_ceiling="client_operator",
    ))
    queued = await http.post(
        f"/agents/{ids['agent_a']}/commands",
        json={"kind": "scan_updates", "payload": {}},
        headers=operator,
    )
    assert queued.status_code == 200, queued.text
    assert queued.headers["NodeLink-API-Version"] == public_api.API_REVISION
    async with AsyncSessionLocal() as db:
        command = await db.get(Command, queued.json()["id"])
        dispatched = (
            await db.execute(select(AuditEvent).where(AuditEvent.action == "command.dispatched"))
        ).scalars().one()
    # Provenance stays the human owner; the audit chain also names the token.
    assert command.actor_operator_id == ids["owner"]
    token_id = (await http.get("/api-tokens", headers=sessions["owner"])).json()["items"][0]["id"]
    assert dispatched.actor == f"owner@nodelink.test [api_token:{token_id}]"


async def test_ceilings_cannot_exceed_the_owner(env):
    http, ids, sessions = env
    too_high = await http.post(
        "/api-tokens", headers=sessions["owner"],
        json={"name": "x", "client_id": ids["client_a"], "role_ceiling": "admin"},
    )
    assert too_high.status_code == 422
    assert too_high.json()["detail"]["code"] == "api_token_role_ceiling_exceeds_role"
    over_client = await http.post(
        "/api-tokens", headers=sessions["owner"],
        json={"name": "x", "client_id": ids["client_a"], "client_role_ceiling": "client_admin"},
    )
    assert over_client.status_code == 422
    assert over_client.json()["detail"]["code"] == "api_token_client_role_ceiling_exceeds_membership"
    foreign = await http.post(
        "/api-tokens", headers=sessions["other"],
        json={"name": "x", "client_id": ids["client_b"]},
    )
    assert foreign.status_code == 404
    ttl = await http.post(
        "/api-tokens", headers=sessions["owner"],
        json={"name": "x", "client_id": ids["client_a"], "expires_in_days": settings.api_token_max_ttl_days + 1},
    )
    assert ttl.status_code == 422
    assert ttl.json()["detail"]["code"] == "api_token_ttl_exceeds_maximum"


async def test_active_token_cap(env, monkeypatch):
    http, ids, sessions = env
    monkeypatch.setattr(settings, "api_token_max_active_per_operator", 2)
    first = await _mint(http, sessions["owner"], ids["client_a"])
    await _mint(http, sessions["owner"], ids["client_a"])
    capped = await http.post(
        "/api-tokens", headers=sessions["owner"],
        json={"name": "x", "client_id": ids["client_a"]},
    )
    assert capped.status_code == 409
    assert capped.json()["detail"]["code"] == "api_token_limit_reached"
    await http.delete(f"/api-tokens/{first['id']}", headers=sessions["owner"])
    await _mint(http, sessions["owner"], ids["client_a"])


async def test_token_is_refused_off_the_public_surface(env):
    http, ids, sessions = env
    token = _bearer(await _mint(
        http, sessions["owner"], ids["client_a"],
        role_ceiling="operator", client_role_ceiling="client_operator",
    ))
    for method, path in (
        ("GET", "/clients"),
        ("GET", "/audit/events"),
        ("GET", "/api-tokens"),
        ("POST", "/api-tokens"),
        ("GET", "/auth/me"),
        ("GET", "/auth/sessions"),
        ("POST", f"/agents/{ids['agent_a']}/quarantine"),
        ("GET", "/monitoring/webhook-endpoints"),
    ):
        resp = await http.request(method, path, headers=token, json={} if method == "POST" else None)
        assert resp.status_code == 401, (method, path, resp.status_code)
        assert resp.json()["detail"] == "Invalid or expired token"
    # The public discovery route works and advertises the contract.
    version = await http.get("/api-version", headers=token)
    assert version.status_code == 200
    assert version.json()["api_revision"] == public_api.API_REVISION
    assert version.json()["webhook_api_versions"] == ["2026-08-05"]


async def test_token_cannot_satisfy_step_up_or_mint_tokens(env):
    """Even if a token-management route became public, step-up refuses it."""
    from fastapi import HTTPException

    from app.api.deps import require_mfa_verified, require_step_up

    http, ids, sessions = env
    token = await _mint(http, sessions["owner"], ids["client_a"])
    async with AsyncSessionLocal() as db:
        principal = await api_tokens.authenticate(
            db, token["token"], method="GET", route_path="/api/v1/api-version"
        )
        for gate in (require_step_up, require_mfa_verified):
            with pytest.raises(HTTPException) as refused:
                await gate(operator=principal, db=db)
            assert refused.value.status_code == 403
            assert refused.value.detail["code"] == "api_token_not_permitted"
        assert principal.is_platform_admin is False
        assert principal not in db  # transient: caps can never be flushed


@pytest.mark.parametrize("kill", ["revoke", "expire", "disable", "logout_all", "membership"])
async def test_every_kill_switch_ends_the_token(env, kill):
    http, ids, sessions = env
    created = await _mint(http, sessions["owner"], ids["client_a"])
    token = _bearer(created)
    assert (await http.get("/api-version", headers=token)).status_code == 200

    if kill == "revoke":
        revoked = await http.delete(f"/api-tokens/{created['id']}", headers=sessions["owner"])
        assert revoked.status_code == 200 and revoked.json()["active"] is False
        again = await http.delete(f"/api-tokens/{created['id']}", headers=sessions["owner"])
        assert again.status_code == 200  # idempotent, audited once
    else:
        async with AsyncSessionLocal() as db:
            owner = await db.get(Operator, ids["owner"])
            row = await db.get(ApiToken, created["id"])
            if kill == "expire":
                row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            elif kill == "disable":
                owner.disabled = True
            elif kill == "logout_all":
                owner.token_generation += 1
            elif kill == "membership":
                membership = (await db.execute(select(OperatorClientMembership).where(
                    OperatorClientMembership.operator_id == ids["owner"],
                    OperatorClientMembership.client_id == ids["client_a"],
                ))).scalar_one()
                await db.delete(membership)
            await db.commit()

    refused = await http.get("/api-version", headers=token)
    assert refused.status_code == 401
    assert refused.json()["detail"] == "Invalid or expired token"
    if kill == "revoke":
        async with AsyncSessionLocal() as db:
            revoked_events = (await db.execute(
                select(AuditEvent).where(AuditEvent.action == "api_token.revoked")
            )).scalars().all()
        assert len(revoked_events) == 1


async def test_unknown_and_malformed_tokens_are_opaque(env):
    http, _ids, _sessions = env
    for bearer in ("nlk_not-a-real-token", "nlk_", "nlk_" + "A" * 43):
        resp = await http.get("/api-version", headers={"Authorization": f"Bearer {bearer}"})
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid or expired token"


async def test_only_owner_or_platform_admin_can_list_or_revoke(env):
    http, ids, sessions = env
    created = await _mint(http, sessions["owner"], ids["client_a"])
    assert (await http.delete(f"/api-tokens/{created['id']}", headers=sessions["other"])).status_code == 404
    assert (await http.get(f"/api-tokens?operator_id={ids['owner']}", headers=sessions["other"])).status_code == 403
    listed = await http.get(f"/api-tokens?operator_id={ids['owner']}", headers=sessions["platform"])
    assert [t["id"] for t in listed.json()["items"]] == [created["id"]]
    assert (await http.delete(f"/api-tokens/{created['id']}", headers=sessions["platform"])).status_code == 200


async def test_rate_limit_returns_429_with_headers(env, monkeypatch):
    http, ids, sessions = env
    token = _bearer(await _mint(http, sessions["owner"], ids["client_a"]))
    monkeypatch.setattr(api_tokens.request_limiter, "max_failures", 2)
    assert (await http.get("/api-version", headers=token)).status_code == 200
    assert (await http.get("/api-version", headers=token)).status_code == 200
    limited = await http.get("/api-version", headers=token)
    assert limited.status_code == 429
    assert limited.json()["detail"]["code"] == "rate_limited"
    assert int(limited.headers["Retry-After"]) >= 1
    assert limited.headers["RateLimit-Limit"] == "2"
    assert limited.headers["RateLimit-Remaining"] == "0"
    # The owner's dashboard session is not subject to the token budget.
    assert (await http.get("/api-version", headers=sessions["owner"])).status_code == 200


async def test_mutating_budget_is_separate_and_tighter(env, monkeypatch):
    http, ids, sessions = env
    token = _bearer(await _mint(
        http, sessions["owner"], ids["client_a"],
        role_ceiling="operator", client_role_ceiling="client_operator",
    ))
    monkeypatch.setattr(api_tokens.mutating_limiter, "max_failures", 1)
    body = {"kind": "scan_updates", "payload": {}}
    assert (await http.post(f"/agents/{ids['agent_a']}/commands", json=body, headers=token)).status_code == 200
    limited = await http.post(f"/agents/{ids['agent_a']}/commands", json=body, headers=token)
    assert limited.status_code == 429
    # Reads still have budget.
    assert (await http.get(f"/agents/{ids['agent_a']}", headers=token)).status_code == 200


async def test_jwt_audit_rows_are_not_attributed_to_a_previous_token(env):
    """The token attribution never leaks into a later session request."""
    http, ids, sessions = env
    token = _bearer(await _mint(http, sessions["owner"], ids["client_a"]))
    assert (await http.get("/api-version", headers=token)).status_code == 200
    second = await http.post(
        "/api-tokens", headers=sessions["owner"],
        json={"name": "second", "client_id": ids["client_a"]},
    )
    assert second.status_code == 201
    async with AsyncSessionLocal() as db:
        events = (await db.execute(
            select(AuditEvent).where(AuditEvent.action == "api_token.created").order_by(AuditEvent.seq)
        )).scalars().all()
    assert all("[api_token:" not in event.actor for event in events)
