# SPDX-License-Identifier: AGPL-3.0-only
"""Enrollment-token management and secure redemption regression tests."""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import select

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_enrollment_management.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.ratelimit import enrollment_limiter  # noqa: E402
from app.core.security import generate_token, hash_password, hash_token  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    AuditEvent,
    EnrollmentToken,
    Operator,
    OperatorRole,
)


@pytest_asyncio.fixture
async def clients():
    enrollment_limiter.reset()
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                Operator(
                    email="admin@enrollment.test",
                    password_hash=hash_password("admin-password"),
                    role=OperatorRole.admin,
                ),
                Operator(
                    email="viewer@enrollment.test",
                    password_hash=hash_password("viewer-password"),
                    role=OperatorRole.readonly,
                ),
            ]
        )
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test/api/v1") as admin:
        login = await admin.post(
            "/auth/login",
            json={"email": "admin@enrollment.test", "password": "admin-password"},
        )
        admin.headers["Authorization"] = f"Bearer {login.json()['access_token']}"
        async with httpx.AsyncClient(transport=transport, base_url="http://test/api/v1") as viewer:
            login = await viewer.post(
                "/auth/login",
                json={"email": "viewer@enrollment.test", "password": "viewer-password"},
            )
            viewer.headers["Authorization"] = f"Bearer {login.json()['access_token']}"
            yield admin, viewer
    enrollment_limiter.reset()


async def provision(admin: httpx.AsyncClient, **token_overrides):
    organization = (await admin.post("/clients", json={"name": "Enrollment Clinic"})).json()
    site = (
        await admin.post(
            "/sites", json={"client_id": organization["id"], "name": "Tampa"}
        )
    ).json()
    payload = {
        "site_id": site["id"],
        "name": "Deployment token",
        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        **token_overrides,
    }
    token = (await admin.post("/enrollment-tokens", json=payload)).json()
    return organization, site, token


def enroll_payload(token: str, **overrides):
    return {
        "enrollment_token": token,
        "agent_name": "server-agent-01",
        "hostname": "server01.example.local",
        "os": "windows",
        "architecture": "x86_64",
        "environment": "production",
        "supported_command_envelope_versions": ["command-v3"],
        **overrides,
    }


def test_token_generation_and_hashing_are_secure():
    first = generate_token()
    second = generate_token()
    assert first != second
    assert len(first) >= 43  # URL-safe encoding of at least 32 random bytes.
    assert len(hash_token(first)) == 64
    assert hash_token(first) != first
    assert hash_token(first) != hash_token(second)


@pytest.mark.asyncio
async def test_create_list_detail_and_redaction(clients):
    admin, viewer = clients
    organization, site, created = await provision(
        admin,
        description="One-time Tampa enrollment",
        labels=["windows", "production"],
        hostname_restriction="server01.example.local",
    )
    assert created["token"].startswith("nlenr_")
    assert created["status"] == "active"
    assert created["organization_id"] == organization["id"]
    assert created["site_id"] == site["id"]

    listed = (await viewer.get("/enrollment-tokens")).json()
    assert listed["total"] == 1
    serialized = repr(listed)
    assert created["token"] not in serialized
    assert "token_hash" not in serialized
    assert listed["items"][0]["masked_token"].endswith("••••••••")

    detail = (await viewer.get(f"/enrollment-tokens/{created['id']}")).json()
    assert "token" not in detail
    assert detail["labels"] == ["windows", "production"]


@pytest.mark.asyncio
async def test_viewer_cannot_create_or_revoke(clients):
    admin, viewer = clients
    _, _, token = await provision(admin)
    create = await viewer.post(
        "/enrollment-tokens",
        json={"site_id": token["site_id"], "name": "not allowed"},
    )
    assert create.status_code == 403
    revoke = await viewer.post(
        f"/enrollment-tokens/{token['id']}/revoke",
        json={"reason": "not allowed"},
    )
    assert revoke.status_code == 403


@pytest.mark.asyncio
async def test_valid_enrollment_enforces_assignments_and_audits(clients):
    admin, _ = clients
    organization, site, token = await provision(
        admin,
        environment="production",
        hostname_restriction="server01.example.local",
        agent_name_restriction="server-agent-01",
        labels=["tier-1"],
    )
    response = await admin.post("/agents/enroll", json=enroll_payload(token["token"]))
    assert response.status_code == 200
    body = response.json()
    assert body["configuration_metadata"]["organization_id"] == organization["id"]
    assert body["configuration_metadata"]["site"] == site["name"]

    async with AsyncSessionLocal() as db:
        agent = await db.get(Agent, body["agent_id"])
        assert agent is not None
        assert agent.site_id == site["id"]
        assert agent.name == "server-agent-01"
        assert agent.labels == ["tier-1"]
        assert agent.enrolled_by_token_id == token["id"]
        event = (
            await db.execute(
                select(AuditEvent).where(AuditEvent.action == "agent.enrolled")
            )
        ).scalar_one()
        assert event.enrollment_token_id == token["id"]
        assert token["token"] not in repr(event.detail)
        assert "token_hash" not in repr(event.detail)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("token_changes", "payload_changes"),
    [
        ({"hostname_restriction": "expected.example"}, {}),
        ({"agent_name_restriction": "expected-agent"}, {}),
        ({"environment": "staging"}, {}),
    ],
)
async def test_restriction_mismatch_is_rejected_without_consuming(
    clients, token_changes, payload_changes
):
    admin, _ = clients
    _, _, token = await provision(admin, **token_changes)
    response = await admin.post(
        "/agents/enroll",
        json=enroll_payload(token["token"], **payload_changes),
    )
    assert response.status_code == 403
    detail = (await admin.get(f"/enrollment-tokens/{token['id']}")).json()
    assert detail["use_count"] == 0


@pytest.mark.asyncio
async def test_expired_revoked_and_invalid_tokens_are_rejected(clients):
    admin, _ = clients
    _, _, expired = await provision(admin)
    async with AsyncSessionLocal() as db:
        row = await db.get(EnrollmentToken, expired["id"])
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await db.commit()
    assert (
        await admin.post("/agents/enroll", json=enroll_payload(expired["token"]))
    ).status_code == 403

    _, _, revoked = await provision(admin)
    assert (
        await admin.post(
            f"/enrollment-tokens/{revoked['id']}/revoke",
            json={"reason": "installer was decommissioned"},
        )
    ).status_code == 200
    assert (
        await admin.post("/agents/enroll", json=enroll_payload(revoked["token"]))
    ).status_code == 403
    assert (
        await admin.post("/agents/enroll", json=enroll_payload("nlenr_invalid"))
    ).status_code == 403


@pytest.mark.asyncio
async def test_single_and_maximum_use_enforcement(clients):
    admin, _ = clients
    _, _, single = await provision(admin)
    assert (
        await admin.post("/agents/enroll", json=enroll_payload(single["token"]))
    ).status_code == 200
    assert (
        await admin.post(
            "/agents/enroll",
            json=enroll_payload(single["token"], hostname="second.example"),
        )
    ).status_code == 403

    _, _, reusable = await provision(admin, max_uses=2)
    for hostname in ("one.example", "two.example"):
        assert (
            await admin.post(
                "/agents/enroll",
                json=enroll_payload(reusable["token"], hostname=hostname),
            )
        ).status_code == 200
    assert (
        await admin.post(
            "/agents/enroll",
            json=enroll_payload(reusable["token"], hostname="three.example"),
        )
    ).status_code == 403


@pytest.mark.asyncio
async def test_concurrent_single_use_allows_exactly_one(clients):
    admin, _ = clients
    _, _, token = await provision(admin)
    responses = await asyncio.gather(
        admin.post(
            "/agents/enroll",
            json=enroll_payload(token["token"], hostname="race-a.example"),
        ),
        admin.post(
            "/agents/enroll",
            json=enroll_payload(token["token"], hostname="race-b.example"),
        ),
    )
    assert sorted(response.status_code for response in responses) == [200, 403]


@pytest.mark.asyncio
async def test_rate_limit_records_failure_without_secret(clients):
    admin, _ = clients
    old_limit = enrollment_limiter.max_failures
    enrollment_limiter.max_failures = 2
    enrollment_limiter.reset()
    try:
        for _ in range(2):
            response = await admin.post(
                "/agents/enroll", json=enroll_payload("nlenr_invalid")
            )
            assert response.status_code == 403
        blocked = await admin.post(
            "/agents/enroll", json=enroll_payload("nlenr_invalid")
        )
        assert blocked.status_code == 429
        assert "Retry-After" in blocked.headers
    finally:
        enrollment_limiter.max_failures = old_limit
        enrollment_limiter.reset()

    async with AsyncSessionLocal() as db:
        events = list(
            (
                await db.execute(
                    select(AuditEvent).where(
                        AuditEvent.action == "agent.enrollment_failed"
                    )
                )
            ).scalars()
        )
        assert len(events) == 3
        assert "nlenr_invalid" not in repr([event.detail for event in events])


@pytest.mark.asyncio
async def test_credential_renewal_and_agent_revocation(clients):
    admin, _ = clients
    _, _, token = await provision(admin)
    enrolled = (
        await admin.post("/agents/enroll", json=enroll_payload(token["token"]))
    ).json()
    old_auth = {"Authorization": f"Bearer {enrolled['agent_token']}"}
    renewed = await admin.post("/agents/credentials/renew", headers=old_auth)
    assert renewed.status_code == 200
    new_auth = {"Authorization": f"Bearer {renewed.json()['agent_token']}"}
    heartbeat = {"supported_command_envelope_versions": ["command-v3"]}
    assert (await admin.post("/heartbeat", json=heartbeat, headers=old_auth)).status_code == 401
    assert (await admin.post("/heartbeat", json=heartbeat, headers=new_auth)).status_code == 200

    revoked = await admin.post(
        f"/agents/{enrolled['agent_id']}/revoke",
        json={"reason": "device retired"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["revoked_at"] is not None
    assert (await admin.post("/heartbeat", json=heartbeat, headers=new_auth)).status_code == 401
