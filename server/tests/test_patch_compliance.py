# SPDX-License-Identifier: AGPL-3.0-only
"""Read-only patch compliance reporting tests (issue #54)."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_patch_compliance.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
_LOGIN = os.environ.setdefault("NODELINK_TEST_LOGIN", "op-pass")
_VIEW_LOGIN = os.environ.setdefault("NODELINK_TEST_VIEW_LOGIN", "view-pass")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import hashlib
import json

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core.command_envelope import COMMAND_ENVELOPE_V3  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    AgentInventorySnapshot,
    AuditEvent,
    Operator,
    OperatorRole,
)


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                Operator(
                    email="compliance-op@nodelink.test",
                    password_hash=hash_password(_LOGIN),
                    role=OperatorRole.operator,
                ),
                Operator(
                    email="compliance-view@nodelink.test",
                    password_hash=hash_password(_VIEW_LOGIN),
                    role=OperatorRole.readonly,
                ),
            ]
        )
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test/api/v1",
    ) as value:
        yield value
    await engine.dispose()


async def auth(client, email="compliance-op@nodelink.test", password=_LOGIN):
    response = await client.post(
        "/auth/login",
        json={"email": email, "password": password},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def enroll(client, headers, *, hostname="PATCH-PC"):
    organization = (
        await client.post(
            "/clients",
            json={"name": f"Compliance {uuid4().hex}"},
            headers=headers,
        )
    ).json()
    site = (
        await client.post(
            "/sites",
            json={"client_id": organization["id"], "name": "HQ"},
            headers=headers,
        )
    ).json()
    agent_id = await enroll_at_site(client, headers, site["id"], hostname=hostname)
    return organization["id"], site["id"], agent_id


async def enroll_at_site(client, headers, site_id, *, hostname):
    token = (
        await client.post(
            "/enrollment-tokens",
            json={"site_id": site_id},
            headers=headers,
        )
    ).json()["token"]
    response = await client.post(
        "/enroll",
        json={
            "enrollment_token": token,
            "hostname": hostname,
            "os": "windows",
            "supported_command_envelope_versions": [COMMAND_ENVELOPE_V3],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["agent_id"]


async def seed_updates(
    agent_id,
    missing,
    *,
    collected_at=None,
    received_at=None,
):
    payload = {"missing": missing, "installed": []}
    encoded = json.dumps(payload).encode()
    async with AsyncSessionLocal() as db:
        db.add(
            AgentInventorySnapshot(
                agent_id=agent_id,
                section="windows_updates",
                status="ok",
                schema_version=1,
                content_hash=hashlib.sha256(encoded).hexdigest(),
                byte_size=len(encoded),
                payload=payload,
                collected_at=collected_at or datetime.now(timezone.utc),
                received_at=received_at or datetime.now(timezone.utc),
            )
        )
        await db.commit()


def update(kb, classification=None, severity=None, days_old=None):
    item = {
        "title": f"Update {kb}",
        "kb_id": kb,
        "update_id": None,
        "classification": classification,
        "severity": severity,
    }
    if days_old is not None:
        item["last_deployment_change"] = (
            datetime.now(timezone.utc) - timedelta(days=days_old)
        ).isoformat()
    return item


async def create_site_policy(client, headers, site_id):
    response = await client.post(
        "/patch-approval/policies",
        headers=headers,
        json={
            "name": f"Compliance {uuid4().hex}",
            "scope": "site",
            "scope_id": site_id,
            "default_action": "deny",
            "rules": [
                {
                    "key": "critical",
                    "action": "approve",
                    "match": {"severities": ["Critical"]},
                }
            ],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


@pytest.mark.asyncio
async def test_exempt_and_unknown_states(client):
    operator = await auth(client)
    _, site_id, agent_id = await enroll(client, operator)

    exempt = await client.get(f"/agents/{agent_id}/patch-compliance", headers=operator)
    assert exempt.status_code == 200, exempt.text
    assert exempt.json()["state"] == "exempt"

    await create_site_policy(client, operator, site_id)
    unknown = await client.get(f"/agents/{agent_id}/patch-compliance", headers=operator)
    assert unknown.status_code == 200, unknown.text
    assert unknown.json()["state"] == "unknown"


@pytest.mark.asyncio
async def test_stale_compliant_and_non_compliant_states(client):
    operator = await auth(client)

    _, stale_site, stale_agent = await enroll(client, operator, hostname="STALE-PC")
    await create_site_policy(client, operator, stale_site)
    await seed_updates(
        stale_agent,
        [update("KB-STALE", severity="Critical")],
        collected_at=datetime.now(timezone.utc) - timedelta(hours=48),
    )
    stale = await client.get(f"/agents/{stale_agent}/patch-compliance", headers=operator)
    assert stale.status_code == 200, stale.text
    assert stale.json()["state"] == "stale"

    _, compliant_site, compliant_agent = await enroll(
        client,
        operator,
        hostname="COMPLIANT-PC",
    )
    await create_site_policy(client, operator, compliant_site)
    await seed_updates(
        compliant_agent,
        [update("KB-DENIED", classification="Definition Updates")],
    )
    compliant = await client.get(
        f"/agents/{compliant_agent}/patch-compliance",
        headers=operator,
    )
    assert compliant.status_code == 200, compliant.text
    assert compliant.json()["state"] == "compliant"
    assert compliant.json()["denied_missing"] == 1

    _, non_compliant_site, non_compliant_agent = await enroll(
        client,
        operator,
        hostname="NONCOMPLIANT-PC",
    )
    await create_site_policy(client, operator, non_compliant_site)
    await seed_updates(
        non_compliant_agent,
        [update("KB-APPROVED", severity="Critical")],
    )
    non_compliant = await client.get(
        f"/agents/{non_compliant_agent}/patch-compliance",
        headers=operator,
    )
    assert non_compliant.status_code == 200, non_compliant.text
    assert non_compliant.json()["state"] == "non_compliant"
    assert non_compliant.json()["approved_missing"] == 1
    assert non_compliant.json()["decisions"][0]["decision"] == "approve"


@pytest.mark.asyncio
async def test_summary_list_history_exports_readonly_and_audit(client):
    operator = await auth(client)
    readonly = await auth(
        client,
        "compliance-view@nodelink.test",
        _VIEW_LOGIN,
    )
    client_id, site_id, approved_agent = await enroll(
        client,
        operator,
        hostname="APPROVED-MISSING",
    )
    denied_agent = await enroll_at_site(
        client,
        operator,
        site_id,
        hostname="DENIED-MISSING",
    )
    stale_agent = await enroll_at_site(
        client,
        operator,
        site_id,
        hostname="STALE",
    )
    unknown_agent = await enroll_at_site(
        client,
        operator,
        site_id,
        hostname="UNKNOWN",
    )
    policy_id = await create_site_policy(client, operator, site_id)
    now = datetime.now(timezone.utc)
    await seed_updates(
        approved_agent,
        [update("KB-OLD", severity="Critical")],
        collected_at=now - timedelta(days=2),
        received_at=now - timedelta(days=2),
    )
    await seed_updates(
        approved_agent,
        [
            update("KB-NEW", severity="Critical"),
            update("KB-NOT-REQUIRED", classification="Definition Updates"),
        ],
        collected_at=now,
        received_at=now,
    )
    await seed_updates(
        denied_agent,
        [update("KB-DENIED", classification="Definition Updates")],
    )
    await seed_updates(
        stale_agent,
        [update("KB-STALE", severity="Critical")],
        collected_at=now - timedelta(hours=48),
    )

    summary = await client.get(
        f"/patch-compliance/summary?client_id={client_id}&site_id={site_id}",
        headers=readonly,
    )
    assert summary.status_code == 200, summary.text
    assert summary.json() == {
        "total_endpoints": 4,
        "compliant": 1,
        "non_compliant": 1,
        "stale": 1,
        "unknown": 1,
        "exempt": 0,
        "total_approved_missing": 2,
        "truncated": False,
    }

    listing = await client.get(
        f"/patch-compliance?site_id={site_id}&state=non_compliant&page=1&page_size=1",
        headers=readonly,
    )
    assert listing.status_code == 200, listing.text
    assert listing.json()["total"] == 1
    assert listing.json()["truncated"] is False
    assert listing.json()["items"][0]["agent_id"] == approved_agent
    assert (
        await client.get("/patch-compliance?state=not-a-state", headers=readonly)
    ).status_code == 422

    history = await client.get(
        f"/agents/{approved_agent}/patch-compliance/history?limit=2",
        headers=readonly,
    )
    assert history.status_code == 200, history.text
    assert history.json()["policy_id"] == policy_id
    assert history.json()["evaluated_against"] == "current_policy"
    assert [point["approved_missing"] for point in history.json()["points"]] == [1, 1]

    csv_export = await client.get(
        f"/patch-compliance/export?format=csv&site_id={site_id}",
        headers=readonly,
    )
    assert csv_export.status_code == 200, csv_export.text
    assert "patch-compliance-" in csv_export.headers["content-disposition"]
    assert csv_export.text.splitlines()[0] == (
        "client_id,client_name,site_id,site_name,endpoint_id,hostname,state,"
        "policy_id,scanned_at,total_missing,approved_missing,deferred_missing,"
        "denied_missing"
    )

    json_export = await client.get(
        f"/patch-compliance/export?format=json&site_id={site_id}&state=compliant",
        headers=readonly,
    )
    assert json_export.status_code == 200, json_export.text
    assert json_export.json()["truncated"] is False
    assert len(json_export.json()["rows"]) == 1
    assert json_export.json()["rows"][0]["agent_id"] == denied_agent

    async with AsyncSessionLocal() as db:
        events = list(
            (
                await db.execute(
                    select(AuditEvent).where(
                        AuditEvent.action.in_(
                            ["patch_compliance.viewed", "patch_compliance.exported"]
                        )
                    )
                )
            ).scalars().all()
        )
    assert any(event.action == "patch_compliance.viewed" for event in events)
    assert any(event.action == "patch_compliance.exported" for event in events)
    assert unknown_agent
