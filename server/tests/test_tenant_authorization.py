# SPDX-License-Identifier: AGPL-3.0-only
"""Tenant-scoped authorization boundary tests (issue #66).

The core requirement is a default-deny tenant boundary with a 404 anti-oracle:
an operator with membership only in Client A must be unable to see or act on
Client B's resources, and Client B's rows must never appear in any list. A
platform admin crosses the boundary; membership grant/revoke is audited and
invalidates the grantee's outstanding tokens.
"""
from __future__ import annotations

import os

os.environ.setdefault(
    "DATABASE_URL", "sqlite+aiosqlite:///./test_tenant_authorization.db"
)
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")
_PLATFORM_PW = os.environ.setdefault("NODELINK_TEST_PLATFORM_PW", "platform-pw")
_GLOBAL_PW = os.environ.setdefault("NODELINK_TEST_GLOBAL_PW", "global-pw")
_OP_A_PW = os.environ.setdefault("NODELINK_TEST_OP_A_PW", "op-a-pw")
_OP_B_PW = os.environ.setdefault("NODELINK_TEST_OP_B_PW", "op-b-pw")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core import audit  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    AuditEvent,
    Client as RMMClient,
    ClientRole,
    Operator,
    OperatorClientMembership,
    OperatorRole,
    Site,
)


@pytest_asyncio.fixture
async def tenancy():
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        platform = Operator(
            email="platform@nodelink.test",
            password_hash=hash_password(_PLATFORM_PW),
            role=OperatorRole.admin,
            is_platform_admin=True,
        )
        # A global admin who is NOT a platform admin — proves the flag is
        # independent of the global role (default-deny for new admins).
        global_admin = Operator(
            email="global-admin@nodelink.test",
            password_hash=hash_password(_GLOBAL_PW),
            role=OperatorRole.admin,
        )
        op_a = Operator(
            email="op-a@nodelink.test",
            password_hash=hash_password(_OP_A_PW),
            role=OperatorRole.operator,
        )
        op_b = Operator(
            email="op-b@nodelink.test",
            password_hash=hash_password(_OP_B_PW),
            role=OperatorRole.operator,
        )
        client_a = RMMClient(name="Alpha Clinic")
        client_b = RMMClient(name="Bravo Corp")
        db.add_all([platform, global_admin, op_a, op_b, client_a, client_b])
        await db.flush()

        site_a = Site(client_id=client_a.id, name="A-HQ")
        site_b = Site(client_id=client_b.id, name="B-HQ")
        db.add_all([site_a, site_b])
        await db.flush()

        agent_a = Agent(site_id=site_a.id, token_hash="agent-a-hash", hostname="A-1", os="windows")
        agent_b = Agent(site_id=site_b.id, token_hash="agent-b-hash", hostname="B-1", os="windows")
        db.add_all([agent_a, agent_b])
        await db.flush()

        # op_a is client_operator on A only; op_b is client_operator on B only.
        db.add_all([
            OperatorClientMembership(
                operator_id=op_a.id, client_id=client_a.id,
                role=ClientRole.client_operator, granted_by="seed", reason="seed",
            ),
            OperatorClientMembership(
                operator_id=op_b.id, client_id=client_b.id,
                role=ClientRole.client_operator, granted_by="seed", reason="seed",
            ),
        ])
        await db.commit()
        ids = {
            "op_a": op_a.id, "op_b": op_b.id,
            "global_admin": global_admin.id,
            "client_a": client_a.id, "client_b": client_b.id,
            "site_a": site_a.id, "site_b": site_b.id,
            "agent_a": agent_a.id, "agent_b": agent_b.id,
        }

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as client:
        async def login(email: str, password: str) -> str:
            resp = await client.post("/auth/login", json={"email": email, "password": password})
            assert resp.status_code == 200, resp.text
            return resp.json()["access_token"]

        tokens = {
            "platform": await login("platform@nodelink.test", _PLATFORM_PW),
            "global_admin": await login("global-admin@nodelink.test", _GLOBAL_PW),
            "op_a": await login("op-a@nodelink.test", _OP_A_PW),
            "op_b": await login("op-b@nodelink.test", _OP_B_PW),
        }
        yield client, ids, tokens
    await engine.dispose()


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_cross_tenant_reads_are_404_and_lists_exclude(tenancy):
    """op_a (Client A only) cannot see any of Client B, by list or by id."""
    client, ids, tokens = tenancy
    a = _auth(tokens["op_a"])

    # Lists show only Client A.
    clients = (await client.get("/clients", headers=a)).json()
    assert [c["id"] for c in clients] == [ids["client_a"]]

    agents = (await client.get("/agents", headers=a)).json()
    assert [g["id"] for g in agents] == [ids["agent_a"]]

    endpoints = (await client.get("/endpoints", headers=a)).json()
    assert {e["id"] for e in endpoints["items"]} == {ids["agent_a"]}

    # Direct-id access to Client B resources is 404 (anti-oracle), not 403.
    for path in (
        f"/clients/{ids['client_b']}",
        f"/sites/{ids['site_b']}",
        f"/agents/{ids['agent_b']}",
        f"/endpoints/{ids['agent_b']}",
        f"/agents/{ids['agent_b']}/commands",
        f"/agents/{ids['agent_b']}/patch-compliance",
        f"/endpoints/{ids['agent_b']}/inventory",
    ):
        resp = await client.get(path, headers=a)
        assert resp.status_code == 404, f"{path} -> {resp.status_code}"

    # Own tenant still works.
    assert (await client.get(f"/agents/{ids['agent_a']}", headers=a)).status_code == 200


@pytest.mark.asyncio
async def test_platform_admin_sees_all_tenants(tenancy):
    client, ids, tokens = tenancy
    p = _auth(tokens["platform"])
    clients = (await client.get("/clients", headers=p)).json()
    assert {c["id"] for c in clients} == {ids["client_a"], ids["client_b"]}
    agents = (await client.get("/agents", headers=p)).json()
    assert {g["id"] for g in agents} == {ids["agent_a"], ids["agent_b"]}
    assert (await client.get(f"/agents/{ids['agent_b']}", headers=p)).status_code == 200


@pytest.mark.asyncio
async def test_non_platform_global_admin_is_default_deny(tenancy):
    """A global admin without the platform flag and without memberships sees
    nothing — the flag is independent of the global role."""
    client, ids, tokens = tenancy
    g = _auth(tokens["global_admin"])
    assert (await client.get("/clients", headers=g)).json() == []
    assert (await client.get(f"/agents/{ids['agent_a']}", headers=g)).status_code == 404


@pytest.mark.asyncio
async def test_cross_tenant_dispatch_is_404_and_audited(tenancy):
    """A dispatch at another tenant's agent fails closed as 404 and records a
    tenant.access_denied abuse event."""
    client, ids, tokens = tenancy
    a = _auth(tokens["op_a"])
    resp = await client.post(
        f"/agents/{ids['agent_b']}/commands",
        json={"kind": "scan_updates", "payload": {}},
        headers=a,
    )
    assert resp.status_code == 404
    async with AsyncSessionLocal() as db:
        events = list(
            (
                await db.execute(
                    select(AuditEvent).where(
                        AuditEvent.action == "tenant.access_denied"
                    )
                )
            ).scalars().all()
        )
    assert len(events) == 1
    assert events[0].detail["resource"] == "command"
    assert events[0].detail["agent_id"] == ids["agent_b"]


@pytest.mark.asyncio
async def test_membership_grant_and_revoke_lifecycle(tenancy):
    """Grant/revoke is platform-admin only, audited with a reason, and bumps the
    grantee's token generation so outstanding tokens are rejected immediately."""
    client, ids, tokens = tenancy
    p = _auth(tokens["platform"])
    op_a_token = tokens["op_a"]

    # Before: op_a cannot see Client B.
    assert (await client.get(f"/clients/{ids['client_b']}", headers=_auth(op_a_token))).status_code == 404

    grant = await client.post(
        f"/auth/operators/{ids['op_a']}/client-memberships",
        json={"client_id": ids["client_b"], "role": "client_readonly", "reason": "cover B"},
        headers=p,
    )
    assert grant.status_code == 201

    # The grant invalidated op_a's existing token (generation bump).
    assert (await client.get("/clients", headers=_auth(op_a_token))).status_code == 401

    # A fresh token sees both tenants now.
    new_token = (await client.post(
        "/auth/login", json={"email": "op-a@nodelink.test", "password": _OP_A_PW}
    )).json()["access_token"]
    clients = (await client.get("/clients", headers=_auth(new_token))).json()
    assert {c["id"] for c in clients} == {ids["client_a"], ids["client_b"]}

    # Revoke, then a fresh token loses B again.
    revoke = await client.post(
        f"/auth/operators/{ids['op_a']}/client-memberships/{ids['client_b']}/revoke",
        json={"reason": "no longer needed"},
        headers=p,
    )
    assert revoke.status_code == 204
    newer = (await client.post(
        "/auth/login", json={"email": "op-a@nodelink.test", "password": _OP_A_PW}
    )).json()["access_token"]
    clients = (await client.get("/clients", headers=_auth(newer))).json()
    assert {c["id"] for c in clients} == {ids["client_a"]}

    # Both membership events are audited and anchored to Client B.
    async with AsyncSessionLocal() as db:
        events = {
            e.action: e
            for e in (
                await db.execute(
                    select(AuditEvent).where(
                        AuditEvent.action.in_([
                            "operator.tenant_membership_granted",
                            "operator.tenant_membership_revoked",
                        ])
                    )
                )
            ).scalars().all()
        }
    assert set(events) == {
        "operator.tenant_membership_granted",
        "operator.tenant_membership_revoked",
    }
    assert events["operator.tenant_membership_granted"].organization_id == ids["client_b"]

    # The audit chain still verifies after all this activity.
    async with AsyncSessionLocal() as db:
        ok, broken = await audit.verify_chain(db)
    assert ok, broken


@pytest.mark.asyncio
async def test_membership_admin_requires_platform_admin(tenancy):
    """A global admin without the platform flag cannot administer memberships."""
    client, ids, tokens = tenancy
    g = _auth(tokens["global_admin"])
    resp = await client.post(
        f"/auth/operators/{ids['op_a']}/client-memberships",
        json={"client_id": ids["client_a"], "role": "client_readonly", "reason": "x"},
        headers=g,
    )
    assert resp.status_code == 403
    assert (await client.get(f"/auth/operators/{ids['op_a']}/client-memberships", headers=g)).status_code == 403


@pytest.mark.asyncio
async def test_audit_timeline_is_tenant_scoped(tenancy):
    """op_a's audit timeline shows only events anchored to Client A."""
    client, ids, tokens = tenancy
    p = _auth(tokens["platform"])
    a = _auth(tokens["op_a"])

    # Generate a Client-B-anchored event as the platform admin (create a site).
    created = await client.post(
        "/sites", json={"client_id": ids["client_b"], "name": "B-2"}, headers=p
    )
    assert created.status_code == 201

    events = (await client.get("/audit/events", headers=a)).json()["items"]
    orgs = {e["organization_id"] for e in events}
    # Only Client A (or unanchored self-view events are excluded entirely).
    assert ids["client_b"] not in orgs
    assert orgs <= {ids["client_a"]}


@pytest.mark.asyncio
async def test_cannot_remove_last_platform_admin(tenancy):
    client, ids, tokens = tenancy
    p = _auth(tokens["platform"])
    # Resolve the platform admin's own id via /auth/me.
    me = (await client.get("/auth/me", headers=p)).json()
    resp = await client.put(
        f"/auth/operators/{me['id']}/platform-admin",
        json={"is_platform_admin": False, "reason": "attempt lockout"},
        headers=p,
    )
    assert resp.status_code == 409
    assert resp.json()["detail"]["code"] == "last_platform_admin_required"
