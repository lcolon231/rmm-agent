# SPDX-License-Identifier: AGPL-3.0-only
"""HTTP coverage for probe, metrics, signing-key and enrollment views (#284).

These routes had no HTTP test: the liveness/readiness probes and Prometheus
text that deployments scrape, the redacted signing-key lifecycle view, and the
tenant-scoped enrollment dashboard.
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_operational_routes.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest_asyncio  # noqa: E402

import app.main as main_module  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V2  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import Operator, OperatorClientMembership, OperatorRole  # noqa: E402
from tests._tenancy import grant_all_memberships  # noqa: E402

ADMIN = ("ops-admin@nodelink.test", "admin-pass")
VIEWER = ("ops-viewer@nodelink.test", "viewer-pass")
OUTSIDER = ("ops-outsider@nodelink.test", "outsider-pass")


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        for email, password, role in (
            (*ADMIN, OperatorRole.admin),
            (*VIEWER, OperatorRole.readonly),
            (*OUTSIDER, OperatorRole.readonly),
        ):
            db.add(Operator(email=email, password_hash=hash_password(password), role=role))
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        yield c
    await engine.dispose()


async def _auth(c, who) -> dict:
    login = await c.post("/api/v1/auth/login", json={"email": who[0], "password": who[1]})
    assert login.status_code == 200, login.text
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


async def _enroll_one(c, admin: dict) -> None:
    cl = (await c.post("/api/v1/clients", json={"name": "Ops Clinic"}, headers=admin)).json()
    st = (
        await c.post("/api/v1/sites", json={"client_id": cl["id"], "name": "HQ"}, headers=admin)
    ).json()
    et = (
        await c.post(
            "/api/v1/enrollment-tokens", json={"site_id": st["id"], "max_uses": 2}, headers=admin
        )
    ).json()
    enrolled = await c.post(
        "/api/v1/enroll",
        json={
            "enrollment_token": et["token"],
            "hostname": "PC-OPS",
            "os": "windows",
            "supported_command_envelope_versions": [COMMAND_ENVELOPE_V2],
        },
    )
    assert enrolled.status_code == 200, enrolled.text


async def test_liveness_and_readiness_probes(client):
    live = await client.get("/healthz")
    assert live.status_code == 200
    assert live.json()["status"] == "ok"
    ready = await client.get("/readyz")
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"
    assert ready.headers["X-Request-ID"]


async def test_readiness_fails_closed_when_database_is_unreachable(client, monkeypatch):
    class _Broken:
        async def __aenter__(self):
            raise ConnectionError("db down")

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(main_module, "AsyncSessionLocal", lambda: _Broken())
    ready = await client.get("/readyz")
    assert ready.status_code == 503
    assert ready.json()["detail"] == "Database is unavailable"
    # Liveness does not depend on the database.
    assert (await client.get("/healthz")).status_code == 200


async def test_metrics_exposes_agent_status_counts(client):
    admin = await _auth(client, ADMIN)
    await _enroll_one(client, admin)
    scraped = await client.get("/metrics")
    assert scraped.status_code == 200
    assert scraped.headers["content-type"].startswith("text/plain")
    assert "nodelink_" in scraped.text


async def test_signing_keys_are_listed_without_key_material(client):
    viewer = await _auth(client, VIEWER)
    assert (await client.get("/api/v1/signing-keys")).status_code == 401
    listed = await client.get("/api/v1/signing-keys", headers=viewer)
    assert listed.status_code == 200, listed.text
    body = listed.json()
    assert body["active_key_id"]
    assert any(key["active"] for key in body["keys"])
    assert "PRIVATE KEY" not in listed.text and "PUBLIC KEY" not in listed.text


async def test_enrollment_dashboard_is_tenant_scoped(client):
    admin = await _auth(client, ADMIN)
    await _enroll_one(client, admin)
    async with AsyncSessionLocal() as db:
        # Only the viewer is granted the client; the outsider has no membership.
        await grant_all_memberships(db)
        outsider = (
            await db.execute(
                Operator.__table__.select().where(Operator.email == OUTSIDER[0])
            )
        ).first()
        await db.execute(
            OperatorClientMembership.__table__.delete().where(
                OperatorClientMembership.operator_id == outsider.id
            )
        )
        await db.commit()

    viewer = await _auth(client, VIEWER)
    seen = await client.get("/api/v1/enrollment-dashboard", headers=viewer)
    assert seen.status_code == 200, seen.text
    body = seen.json()
    assert body["total_agents"] == 1
    assert body["active_enrollment_tokens"] == 1
    assert [agent["hostname"] for agent in body["recently_enrolled_agents"]] == ["PC-OPS"]

    hidden = await client.get(
        "/api/v1/enrollment-dashboard", headers=await _auth(client, OUTSIDER)
    )
    assert hidden.status_code == 200
    assert hidden.json()["total_agents"] == 0
    assert hidden.json()["recently_enrolled_agents"] == []
