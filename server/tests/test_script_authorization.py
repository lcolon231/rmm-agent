# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit arbitrary-script authorization policy tests (issue #111)."""
from __future__ import annotations

import os

os.environ.setdefault(
    "DATABASE_URL", "sqlite+aiosqlite:///./test_script_authorization.db"
)
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

from app.core.command_envelope import COMMAND_ENVELOPE_V2  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    AuditEvent,
    Client as RMMClient,
    Command,
    Operator,
    OperatorRole,
    Site,
)
from tests._tenancy import grant_all_memberships  # noqa: E402


@pytest_asyncio.fixture
async def policy():
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        admin = Operator(
            email="policy-admin@nodelink.test",
            password_hash=hash_password("admin-password"),
            role=OperatorRole.admin,
            is_platform_admin=True,
        )
        operator = Operator(
            email="policy-operator@nodelink.test",
            password_hash=hash_password("operator-password"),
            role=OperatorRole.operator,
        )
        readonly = Operator(
            email="policy-viewer@nodelink.test",
            password_hash=hash_password("viewer-password"),
            role=OperatorRole.readonly,
        )
        tenant = RMMClient(name="Policy Clinic")
        db.add_all([admin, operator, readonly, tenant])
        await db.flush()
        site_one = Site(client_id=tenant.id, name="North")
        site_two = Site(client_id=tenant.id, name="South")
        db.add_all([site_one, site_two])
        await db.flush()
        agent_one = Agent(
            site_id=site_one.id,
            token_hash="policy-agent-one",
            hostname="POLICY-ONE",
            os="windows",
            command_envelope_versions=[COMMAND_ENVELOPE_V2],
        )
        agent_two = Agent(
            site_id=site_two.id,
            token_hash="policy-agent-two",
            hostname="POLICY-TWO",
            os="windows",
            command_envelope_versions=[COMMAND_ENVELOPE_V2],
        )
        db.add_all([agent_one, agent_two])
        await grant_all_memberships(db)
        await db.commit()
        ids = {
            "admin": admin.id,
            "operator": operator.id,
            "readonly": readonly.id,
            "site_one": site_one.id,
            "site_two": site_two.id,
            "agent_one": agent_one.id,
            "agent_two": agent_two.id,
        }

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://t/api/v1"
    ) as client:
        yield client, ids
    await engine.dispose()


async def _auth(client: httpx.AsyncClient, email: str, password: str) -> dict:
    response = await client.post(
        "/auth/login", json={"email": email, "password": password}
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def _grant(
    client: httpx.AsyncClient,
    admin_auth: dict,
    operator_id: str,
    scope: str,
    scope_id: str | None = None,
):
    body = {"scope": scope, "reason": f"permit {scope} script operations"}
    if scope_id is not None:
        body["scope_id"] = scope_id
    return await client.put(
        f"/auth/operators/{operator_id}/script-permission",
        json=body,
        headers=admin_auth,
    )


async def _dispatch(
    client: httpx.AsyncClient,
    auth: dict,
    agent_id: str,
    kind: str = "shell",
):
    payload = {} if kind == "collect_inventory" else {"script": "echo policy"}
    return await client.post(
        f"/agents/{agent_id}/commands",
        json={"kind": kind, "payload": payload},
        headers=auth,
    )


@pytest.mark.asyncio
async def test_scripts_default_deny_for_operator_and_admin_and_audit(policy):
    client, ids = policy
    operator_auth = await _auth(
        client, "policy-operator@nodelink.test", "operator-password"
    )
    admin_auth = await _auth(
        client, "policy-admin@nodelink.test", "admin-password"
    )

    for auth, kind in ((operator_auth, "shell"), (admin_auth, "powershell")):
        response = await _dispatch(client, auth, ids["agent_one"], kind)
        assert response.status_code == 403
        assert response.json()["detail"]["code"] == "script_execution_not_authorized"

    async with AsyncSessionLocal() as db:
        command_count = await db.scalar(select(func.count()).select_from(Command))
        denials = (
            await db.execute(
                select(AuditEvent)
                .where(AuditEvent.action == "command.authorization_denied")
                .order_by(AuditEvent.seq)
            )
        ).scalars().all()
    assert command_count == 0
    assert [event.detail["reason"] for event in denials] == [
        "script_permission_missing",
        "script_permission_missing",
    ]
    assert all("payload" not in event.detail for event in denials)
    assert all("echo policy" not in str(event.detail) for event in denials)


@pytest.mark.asyncio
async def test_typed_inventory_is_independently_role_authorized(policy):
    client, ids = policy
    operator_auth = await _auth(
        client, "policy-operator@nodelink.test", "operator-password"
    )
    response = await _dispatch(
        client, operator_auth, ids["agent_one"], "collect_inventory"
    )
    assert response.status_code == 200

    async with AsyncSessionLocal() as db:
        allowed = await db.scalar(
            select(AuditEvent).where(
                AuditEvent.action == "command.authorization_allowed"
            )
        )
    assert allowed is not None
    assert allowed.detail["policy"] == "typed_operation"
    assert allowed.detail["permission_scope"] is None


@pytest.mark.asyncio
async def test_global_permission_allows_script_and_is_audited(policy):
    client, ids = policy
    admin_auth = await _auth(
        client, "policy-admin@nodelink.test", "admin-password"
    )
    operator_auth = await _auth(
        client, "policy-operator@nodelink.test", "operator-password"
    )
    grant = await _grant(
        client, admin_auth, ids["operator"], "global"
    )
    assert grant.status_code == 200
    assert grant.json()["script_execution_scope"] == "global"
    assert grant.json()["script_execution_scope_id"] is None

    response = await _dispatch(client, operator_auth, ids["agent_two"])
    assert response.status_code == 200
    async with AsyncSessionLocal() as db:
        actions = (
            await db.execute(
                select(AuditEvent.action, AuditEvent.detail).where(
                    AuditEvent.action.in_(
                        [
                            "operator.script_permission_changed",
                            "command.authorization_allowed",
                        ]
                    )
                )
            )
        ).all()
    assert {action for action, _ in actions} == {
        "operator.script_permission_changed",
        "command.authorization_allowed",
    }
    allowed_detail = next(
        detail for action, detail in actions
        if action == "command.authorization_allowed"
    )
    assert allowed_detail["permission_scope"] == "global"
    assert "payload" not in allowed_detail


@pytest.mark.asyncio
async def test_site_and_agent_scopes_match_only_their_targets(policy):
    client, ids = policy
    admin_auth = await _auth(
        client, "policy-admin@nodelink.test", "admin-password"
    )
    operator_auth = await _auth(
        client, "policy-operator@nodelink.test", "operator-password"
    )

    assert (
        await _grant(
            client,
            admin_auth,
            ids["operator"],
            "site",
            ids["site_one"],
        )
    ).status_code == 200
    assert (await _dispatch(client, operator_auth, ids["agent_one"])).status_code == 200
    assert (await _dispatch(client, operator_auth, ids["agent_two"])).status_code == 403

    assert (
        await _grant(
            client,
            admin_auth,
            ids["operator"],
            "agent",
            ids["agent_two"],
        )
    ).status_code == 200
    assert (await _dispatch(client, operator_auth, ids["agent_one"])).status_code == 403
    assert (await _dispatch(client, operator_auth, ids["agent_two"])).status_code == 200


@pytest.mark.asyncio
async def test_readonly_role_cannot_receive_or_use_script_permission(policy):
    client, ids = policy
    admin_auth = await _auth(
        client, "policy-admin@nodelink.test", "admin-password"
    )
    readonly_auth = await _auth(
        client, "policy-viewer@nodelink.test", "viewer-password"
    )
    grant = await _grant(
        client, admin_auth, ids["readonly"], "global"
    )
    assert grant.status_code == 409
    assert grant.json()["detail"]["code"] == "script_permission_role_ineligible"

    denied = await _dispatch(
        client, readonly_auth, ids["agent_one"], "collect_inventory"
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["code"] == "command_role_not_authorized"
    async with AsyncSessionLocal() as db:
        event = await db.scalar(
            select(AuditEvent)
            .where(
                AuditEvent.action == "command.authorization_denied",
                AuditEvent.actor == "policy-viewer@nodelink.test",
            )
            .order_by(AuditEvent.seq.desc())
        )
    assert event is not None
    assert event.detail["reason"] == "operator_role_insufficient"


@pytest.mark.asyncio
async def test_revoke_restores_default_deny_and_endpoint_view_exposes_match(policy):
    client, ids = policy
    admin_auth = await _auth(
        client, "policy-admin@nodelink.test", "admin-password"
    )
    operator_auth = await _auth(
        client, "policy-operator@nodelink.test", "operator-password"
    )
    assert (
        await _grant(
            client,
            admin_auth,
            ids["operator"],
            "site",
            ids["site_one"],
        )
    ).status_code == 200

    allowed_detail = await client.get(
        f"/endpoints/{ids['agent_one']}", headers=operator_auth
    )
    denied_detail = await client.get(
        f"/endpoints/{ids['agent_two']}", headers=operator_auth
    )
    assert allowed_detail.json()["script_execution_allowed"] is True
    assert denied_detail.json()["script_execution_allowed"] is False

    revoked = await client.post(
        f"/auth/operators/{ids['operator']}/script-permission/revoke",
        json={"reason": "maintenance window ended"},
        headers=admin_auth,
    )
    assert revoked.status_code == 200
    assert revoked.json()["script_execution_scope"] is None
    assert (
        await _dispatch(client, operator_auth, ids["agent_one"])
    ).status_code == 403
