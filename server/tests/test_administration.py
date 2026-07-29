# SPDX-License-Identifier: AGPL-3.0-only
"""Client/site onboarding and operator-administration regression tests."""
from __future__ import annotations

import os

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_administration.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    AuditEvent,
    Operator,
    OperatorRole,
    ScriptExecutionScope,
)


@pytest_asyncio.fixture
async def administration():
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        operators = [
            Operator(
                email="primary-admin@nodelink.test",
                password_hash=hash_password("primary-password"),
                role=OperatorRole.admin,
            ),
            Operator(
                email="backup-admin@nodelink.test",
                password_hash=hash_password("backup-password"),
                role=OperatorRole.admin,
            ),
            Operator(
                email="technician@nodelink.test",
                password_hash=hash_password("technician-password"),
                role=OperatorRole.operator,
                script_execution_scope=ScriptExecutionScope.global_,
            ),
            Operator(
                email="viewer@nodelink.test",
                password_hash=hash_password("viewer-password"),
                role=OperatorRole.readonly,
            ),
        ]
        db.add_all(operators)
        await db.commit()
        ids = {operator.email: operator.id for operator in operators}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test/api/v1",
    ) as client:
        async def login(email: str, password: str) -> str:
            response = await client.post(
                "/auth/login",
                json={"email": email, "password": password},
            )
            assert response.status_code == 200
            return response.json()["access_token"]

        tokens = {
            "primary": await login(
                "primary-admin@nodelink.test", "primary-password"
            ),
            "backup": await login("backup-admin@nodelink.test", "backup-password"),
            "technician": await login(
                "technician@nodelink.test", "technician-password"
            ),
            "viewer": await login("viewer@nodelink.test", "viewer-password"),
        }
        yield client, ids, tokens
    await engine.dispose()


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_first_run_client_site_creation_is_validated_and_audited(
    administration,
):
    client, _, tokens = administration
    headers = _auth(tokens["primary"])

    created_client = await client.post(
        "/clients",
        json={"name": "  North Clinic  "},
        headers=headers,
    )
    assert created_client.status_code == 201
    organization = created_client.json()
    assert organization["name"] == "North Clinic"

    duplicate_client = await client.post(
        "/clients",
        json={"name": "north clinic"},
        headers=headers,
    )
    assert duplicate_client.status_code == 409
    assert duplicate_client.json()["detail"] == {"code": "client_name_exists"}

    created_site = await client.post(
        "/sites",
        json={"client_id": organization["id"], "name": "  Headquarters  "},
        headers=headers,
    )
    assert created_site.status_code == 201
    site = created_site.json()
    assert site["name"] == "Headquarters"

    duplicate_site = await client.post(
        "/sites",
        json={"client_id": organization["id"], "name": "HEADQUARTERS"},
        headers=headers,
    )
    assert duplicate_site.status_code == 409
    assert duplicate_site.json()["detail"] == {"code": "site_name_exists"}
    assert (
        await client.post(
            "/sites",
            json={"client_id": "missing", "name": "HQ"},
            headers=headers,
        )
    ).status_code == 404

    viewer_headers = _auth(tokens["viewer"])
    assert (
        await client.post(
            "/clients",
            json={"name": "Forbidden client"},
            headers=viewer_headers,
        )
    ).status_code == 403
    assert (
        await client.post(
            "/sites",
            json={"client_id": organization["id"], "name": "Forbidden site"},
            headers=viewer_headers,
        )
    ).status_code == 403

    async with AsyncSessionLocal() as db:
        events = list(
            (
                await db.execute(
                    select(AuditEvent).where(
                        AuditEvent.action.in_(["client.created", "site.created"])
                    )
                )
            ).scalars()
        )
    assert [event.action for event in events] == ["client.created", "site.created"]
    assert events[0].organization_id == organization["id"]
    assert events[1].organization_id == organization["id"]
    serialized = repr([event.detail for event in events])
    assert "North Clinic" not in serialized
    assert "Headquarters" not in serialized
    assert all("name_sha256" in event.detail for event in events)


@pytest.mark.asyncio
async def test_operator_creation_normalizes_email_and_never_audits_password(
    administration,
):
    client, _, tokens = administration
    password = "creation-password-sentinel"
    response = await client.post(
        "/auth/operators",
        json={
            "email": "  NEW.OPERATOR@Example.TEST  ",
            "password": password,
            "role": "operator",
        },
        headers=_auth(tokens["primary"]),
    )
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "new.operator@example.test"
    assert password not in repr(body)
    assert "password" not in body
    assert "password_hash" not in body
    assert "access_token" not in body

    duplicate = await client.post(
        "/auth/operators",
        json={
            "email": "NEW.OPERATOR@example.test",
            "password": "different-password",
            "role": "readonly",
        },
        headers=_auth(tokens["primary"]),
    )
    assert duplicate.status_code == 409

    async with AsyncSessionLocal() as db:
        event = await db.scalar(
            select(AuditEvent).where(AuditEvent.action == "operator.created")
        )
    assert event is not None
    assert event.actor == "primary-admin@nodelink.test"
    assert event.actor_user_id is not None
    assert event.detail["operator_id"] == body["id"]
    assert event.detail["operator_role"] == "operator"
    assert "email_sha256" in event.detail
    assert password not in repr(event.detail)
    assert "new.operator@example.test" not in repr(event.detail)


@pytest.mark.asyncio
async def test_role_change_revokes_sessions_and_readonly_script_permission(
    administration,
):
    client, ids, tokens = administration
    target_id = ids["technician@nodelink.test"]
    response = await client.put(
        f"/auth/operators/{target_id}/role",
        json={"role": "readonly", "reason": "Responsibilities changed"},
        headers=_auth(tokens["primary"]),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["role"] == "readonly"
    assert body["script_execution_scope"] is None
    assert body["script_execution_scope_id"] is None

    expired_session = await client.get(
        "/auth/me",
        headers=_auth(tokens["technician"]),
    )
    assert expired_session.status_code == 401

    async with AsyncSessionLocal() as db:
        event = await db.scalar(
            select(AuditEvent).where(AuditEvent.action == "operator.role_changed")
        )
    assert event is not None
    assert event.detail["previous_role"] == "operator"
    assert event.detail["new_role"] == "readonly"
    assert event.detail["script_permission_revoked"] is True
    assert "Responsibilities changed" not in repr(event.detail)
    assert "reason_sha256" in event.detail


@pytest.mark.asyncio
async def test_disable_enable_and_last_active_admin_safety(administration):
    client, ids, tokens = administration
    backup_id = ids["backup-admin@nodelink.test"]
    primary_id = ids["primary-admin@nodelink.test"]
    primary_auth = _auth(tokens["primary"])

    disabled = await client.put(
        f"/auth/operators/{backup_id}/disabled",
        json={"disabled": True, "reason": "Temporary access suspension"},
        headers=primary_auth,
    )
    assert disabled.status_code == 200
    assert disabled.json()["disabled"] is True
    assert (
        await client.get("/auth/me", headers=_auth(tokens["backup"]))
    ).status_code == 401

    last_admin_disable = await client.put(
        f"/auth/operators/{primary_id}/disabled",
        json={"disabled": True, "reason": "Would remove final administrator"},
        headers=primary_auth,
    )
    assert last_admin_disable.status_code == 409
    assert last_admin_disable.json()["detail"] == {
        "code": "last_active_admin_required"
    }
    last_admin_demote = await client.put(
        f"/auth/operators/{primary_id}/role",
        json={"role": "operator", "reason": "Would remove final administrator"},
        headers=primary_auth,
    )
    assert last_admin_demote.status_code == 409
    assert last_admin_demote.json()["detail"] == {
        "code": "last_active_admin_required"
    }

    enabled = await client.put(
        f"/auth/operators/{backup_id}/disabled",
        json={"disabled": False, "reason": "Access restored after review"},
        headers=primary_auth,
    )
    assert enabled.status_code == 200
    assert enabled.json()["disabled"] is False
    assert (
        await client.put(
            f"/auth/operators/{backup_id}/disabled",
            json={"disabled": False, "reason": "No state change"},
            headers=primary_auth,
        )
    ).status_code == 409

    async with AsyncSessionLocal() as db:
        events = list(
            (
                await db.execute(
                    select(AuditEvent)
                    .where(AuditEvent.action == "operator.status_changed")
                    .order_by(AuditEvent.seq)
                )
            ).scalars()
        )
    assert [event.detail["new_disabled"] for event in events] == [True, False]
    assert all("reason_sha256" in event.detail for event in events)


@pytest.mark.asyncio
async def test_non_admin_cannot_change_operator_role_or_status(administration):
    client, ids, tokens = administration
    target_id = ids["viewer@nodelink.test"]
    headers = _auth(tokens["technician"])
    assert (
        await client.put(
            f"/auth/operators/{target_id}/role",
            json={"role": "operator", "reason": "Unauthorized role change"},
            headers=headers,
        )
    ).status_code == 403
    assert (
        await client.put(
            f"/auth/operators/{target_id}/disabled",
            json={"disabled": True, "reason": "Unauthorized status change"},
            headers=headers,
        )
    ).status_code == 403
