# SPDX-License-Identifier: AGPL-3.0-only
"""Refusal branches of the core management API (issue #284).

Covers the fail-closed paths of client/site/enrollment-token/agent/command
management that the feature suites never reach: unknown ids, enrollment-token
policy limits, normalized-name races, orphaned token assignments, script
provenance without a version, a power delay that outlives its maintenance
window, and approval/override spends that lose the conditional update.
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_management_core_refusals.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from fastapi import HTTPException  # noqa: E402

from app.api import management  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V3  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    EnrollmentToken,
    Operator,
    OperatorRole,
    ScriptExecutionScope,
    ScriptLanguage,
    ScriptLibraryItem,
    ScriptVersion,
    Site,
)
from tests._tenancy import grant_all_memberships  # noqa: E402

ADMIN = ("core-admin@nodelink.test", "admin-pass")


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add(
            Operator(
                email=ADMIN[0],
                password_hash=hash_password(ADMIN[1]),
                role=OperatorRole.admin,
                is_platform_admin=True,
                script_execution_scope=ScriptExecutionScope.global_,
            )
        )
        await grant_all_memberships(db)
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as value:
        yield value
    await engine.dispose()


@pytest_asyncio.fixture
async def headers(client):
    response = await client.post("/auth/login", json={"email": ADMIN[0], "password": ADMIN[1]})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def make_site(client, headers):
    organization = (await client.post("/clients", json={"name": f"Core {uuid4().hex}"}, headers=headers)).json()
    site = (await client.post("/sites", json={"client_id": organization["id"], "name": "HQ"}, headers=headers)).json()
    return site


async def enroll(client, headers, capabilities=()):
    site = await make_site(client, headers)
    token = (await client.post("/enrollment-tokens", json={"site_id": site["id"]}, headers=headers)).json()["token"]
    response = await client.post(
        "/enroll",
        json={
            "enrollment_token": token,
            "hostname": "PC-CORE",
            "os": "windows",
            "supported_command_envelope_versions": [COMMAND_ENVELOPE_V3],
            "supported_capabilities": list(capabilities),
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


async def seed_orphan_token(site_id: str) -> str:
    async with AsyncSessionLocal() as db:
        token = EnrollmentToken(site_id=site_id, token_hash=uuid4().hex, token_prefix="nlenr_orphan")
        db.add(token)
        await db.commit()
        return token.id


async def seed_script_version() -> str:
    content = "Write-Output 'hi'"
    async with AsyncSessionLocal() as db:
        item = ScriptLibraryItem(name="Cleanup", normalized_name=f"cleanup-{uuid4().hex}", created_by=ADMIN[0])
        db.add(item)
        await db.flush()
        version = ScriptVersion(
            script_id=item.id,
            version=1,
            language=ScriptLanguage.powershell,
            content=content,
            content_sha256=hashlib.sha256(content.encode()).hexdigest(),
            content_bytes=len(content.encode()),
            supported_platforms=["windows"],
            created_by=ADMIN[0],
        )
        db.add(version)
        await db.commit()
        return version.id


@pytest.mark.parametrize(
    ("method", "path", "body", "detail"),
    [
        ("get", "/sites/{missing}", None, "Site not found"),
        ("post", "/enrollment-tokens", {"site_id": "{missing}"}, "Site not found"),
        ("get", "/enrollment-tokens/{missing}", None, "Enrollment token not found"),
        ("post", "/enrollment-tokens/{missing}/revoke", {"reason": "cleanup"}, "Enrollment token not found"),
        ("get", "/agents/{missing}", None, "Agent not found"),
        ("post", "/agents/{missing}/revoke", {"reason": "cleanup"}, "Agent not found"),
        ("post", "/agents/{missing}/commands", {"kind": "shell", "payload": {"script": "whoami"}}, "Agent not found"),
        ("get", "/agents/{missing}/commands/{missing}", None, "Command not found"),
        ("get", "/audit/anchors/{missing}/verify", None, "Anchor not found"),
    ],
)
async def test_unknown_resource_is_404(client, headers, method, path, body, detail):
    missing = str(uuid4())
    url = path.format(missing=missing)
    if body is not None:
        body = {key: value.format(missing=missing) if isinstance(value, str) else value for key, value in body.items()}
    response = await client.request(method, url, json=body, headers=headers)
    assert response.status_code == 404, response.text
    assert response.json()["detail"] == detail


@pytest.mark.parametrize(
    ("body", "status_code", "detail"),
    [
        ({"assigned_user_id": "unknown-user"}, 404, "Assigned user not found"),
        ({"expires_at": "2000-01-01T00:00:00"}, 422, "Token expiration must be in the future"),
        ({"expires_at": "+31d"}, 422, "Token expiration cannot exceed 30 days"),
        ({"max_uses": 6}, 422, "Maximum uses exceeds deployment policy"),
    ],
)
async def test_enrollment_token_policy_refusals(client, headers, monkeypatch, body, status_code, detail):
    monkeypatch.setattr(settings, "enrollment_token_max_expiry_days", 30)
    monkeypatch.setattr(settings, "enrollment_token_max_uses", 5)
    site = await make_site(client, headers)
    if body.get("expires_at") == "+31d":
        body = {"expires_at": (datetime.now(timezone.utc) + timedelta(days=31)).isoformat()}
    response = await client.post("/enrollment-tokens", json={"site_id": site["id"], **body}, headers=headers)
    assert response.status_code == status_code, response.text
    assert response.json()["detail"] == detail


async def test_client_name_casefold_miss_hits_normalized_index(client, headers):
    first = await client.post("/clients", json={"name": "Straße"}, headers=headers)
    assert first.status_code in (200, 201), first.text
    second = await client.post("/clients", json={"name": "Straße"}, headers=headers)
    assert second.status_code == 409, second.text
    assert second.json()["detail"] == {"code": "client_name_exists"}


async def test_site_name_casefold_miss_hits_normalized_index(client, headers):
    organization = (await client.post("/clients", json={"name": "Site race"}, headers=headers)).json()
    body = {"client_id": organization["id"], "name": "Straße"}
    first = await client.post("/sites", json=body, headers=headers)
    assert first.status_code in (200, 201), first.text
    second = await client.post("/sites", json=body, headers=headers)
    assert second.status_code == 409, second.text
    assert second.json()["detail"] == {"code": "site_name_exists"}


async def test_token_whose_site_is_missing_fails_closed(client, headers):
    token_id = await seed_orphan_token(str(uuid4()))
    response = await client.post(f"/enrollment-tokens/{token_id}/revoke", json={"reason": "cleanup"}, headers=headers)
    assert response.status_code == 500
    assert response.json()["detail"] == "Enrollment token assignment is invalid"


async def test_token_whose_client_is_missing_fails_closed(client, headers):
    async with AsyncSessionLocal() as db:
        site = Site(client_id=str(uuid4()), name="Orphan site")
        db.add(site)
        await db.commit()
        site_id = site.id
    token_id = await seed_orphan_token(site_id)
    response = await client.get(f"/enrollment-tokens/{token_id}", headers=headers)
    assert response.status_code == 500
    assert response.json()["detail"] == "Enrollment token assignment is invalid"


@pytest.mark.parametrize(
    ("provenance", "code"),
    [
        ({"script_parameter_value_set_id": "unknown-set"}, "script_parameter_value_set_requires_version"),
        ({"script_version_id": "unknown-version"}, "script_version_not_found"),
        (
            {"script_version_id": "{version}", "script_parameter_value_set_id": "unknown-set"},
            "script_parameter_value_set_not_found",
        ),
    ],
)
async def test_incoherent_script_provenance_is_refused(client, headers, provenance, code):
    enrollment = await enroll(client, headers)
    if provenance.get("script_version_id") == "{version}":
        provenance = {**provenance, "script_version_id": await seed_script_version()}
    response = await client.post(
        f"/agents/{enrollment['agent_id']}/commands",
        json={"kind": "shell", "payload": {"script": "whoami"}, **provenance},
        headers=headers,
    )
    assert response.status_code == 400, response.text
    assert response.json()["detail"] == {"code": code}


async def test_power_delay_beyond_maintenance_window_is_refused(client, headers):
    enrollment = await enroll(client, headers, capabilities=("power-operations-v1",))
    agent_id = enrollment["agent_id"]
    now = datetime.now(timezone.utc)
    window = await client.post(
        "/monitoring/maintenance-windows",
        json={
            "name": "Short power window",
            "scope": "agent",
            "scope_id": agent_id,
            "starts_at": (now - timedelta(minutes=1)).isoformat(),
            "ends_at": (now + timedelta(seconds=45)).isoformat(),
        },
        headers=headers,
    )
    assert window.status_code == 201, window.text
    response = await client.post(
        f"/agents/{agent_id}/commands",
        json={
            "kind": "reboot",
            "payload": {
                "confirm": True,
                "reason": "Approved operating system maintenance",
                "delay_seconds": 60,
                "user_consent": "confirmed",
            },
        },
        headers=headers,
    )
    assert response.status_code == 409, response.text
    assert response.json()["detail"] == {"code": "power_operation_delay_exceeds_maintenance_window"}


@pytest.mark.parametrize(
    ("spend", "code"),
    [
        (management._spend_approval, "approval_request_already_consumed"),
        (management._spend_emergency_override, "emergency_override_already_consumed"),
    ],
)
async def test_spend_that_matches_no_row_is_conflict(client, spend, code):
    async with AsyncSessionLocal() as db:
        with pytest.raises(HTTPException) as exc:
            await spend(db, str(uuid4()), datetime.now(timezone.utc))
    assert exc.value.status_code == 409
    assert exc.value.detail == {"code": code}
