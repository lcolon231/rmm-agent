# SPDX-License-Identifier: AGPL-3.0-only
"""Patch approval policy CRUD, effective resolution, and install-gate tests (#52)."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_patch_policies.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
# Login values come from the environment (defaulted for local runs) so no
# password literal sits next to an operator identity — the shape a generic
# secret scanner flags as a hardcoded credential.
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
from app.core.scheduler import dispatch_scheduled_tasks_once  # noqa: E402
from app.models.models import (  # noqa: E402
    AgentInventorySnapshot,
    AuditEvent,
    Command,
    CommandKind,
    MaintenanceWindow,
    Operator,
    OperatorRole,
    ScheduleConcurrencyPolicy,
    ScheduleMisfirePolicy,
    ScheduleTargetType,
    ScheduledTask,
)


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                Operator(email="patch-op@nodelink.test", password_hash=hash_password(_LOGIN), role=OperatorRole.operator),
                Operator(email="patch-view@nodelink.test", password_hash=hash_password(_VIEW_LOGIN), role=OperatorRole.readonly),
            ]
        )
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test/api/v1") as value:
        yield value
    await engine.dispose()


async def auth(client, email="patch-op@nodelink.test", password=_LOGIN):
    response = await client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def enroll(client, headers, capabilities=()):
    org = (await client.post("/clients", json={"name": f"Patch {uuid4().hex}"}, headers=headers)).json()
    site = (await client.post("/sites", json={"client_id": org["id"], "name": "HQ"}, headers=headers)).json()
    token = (await client.post("/enrollment-tokens", json={"site_id": site["id"]}, headers=headers)).json()["token"]
    enrollment = (
        await client.post(
            "/enroll",
            json={
                "enrollment_token": token,
                "hostname": "PATCH-PC",
                "os": "windows",
                "supported_command_envelope_versions": [COMMAND_ENVELOPE_V3],
                "supported_capabilities": list(capabilities),
            },
        )
    ).json()
    return org["id"], site["id"], enrollment["agent_id"]


async def seed_updates(agent_id, missing):
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
                collected_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()


def update(kb, classification=None, severity=None, days_old=None, title=None):
    item = {"title": title or f"Update {kb}", "kb_id": kb, "update_id": None,
            "classification": classification, "severity": severity}
    if days_old is not None:
        item["last_deployment_change"] = (
            datetime.now(timezone.utc) - timedelta(days=days_old)
        ).isoformat()
    return item


@pytest.mark.asyncio
async def test_crud_scope_authorization_and_duplicate(client):
    op = await auth(client)
    view = await auth(client, "patch-view@nodelink.test", _VIEW_LOGIN)
    _, site_id, _ = await enroll(client, op)

    body = {"name": "Baseline", "scope": "site", "scope_id": site_id,
            "rules": [{"key": "block-defs", "action": "deny", "match": {"classifications": ["Definition Updates"]}}],
            "default_action": "deny"}
    created = await client.post("/patch-approval/policies", headers=op, json=body)
    assert created.status_code == 201, created.text
    policy_id = created.json()["id"]
    assert created.json()["rule_count"] == 1

    # readonly cannot create
    assert (await client.post("/patch-approval/policies", headers=view, json={**body, "name": "X"})).status_code == 403
    # duplicate name in same scope
    assert (await client.post("/patch-approval/policies", headers=op, json=body)).status_code == 409
    # global scope must not carry a scope_id
    global_bad = await client.post("/patch-approval/policies", headers=op,
                                   json={"name": "G", "scope": "global", "scope_id": site_id, "rules": []})
    assert global_bad.status_code == 422
    # nonexistent scope target
    assert (await client.post("/patch-approval/policies", headers=op, json={"name": "N", "scope": "site", "scope_id": "missing", "rules": []})).status_code == 404

    # revise -> version 2
    revised = await client.put(f"/patch-approval/policies/{policy_id}", headers=op,
                               json={"rules": [], "default_action": "approve", "require_maintenance_window": True})
    assert revised.status_code == 200
    assert revised.json()["current_version"] == 2
    assert revised.json()["require_maintenance_window"] is True

    # list + get
    assert any(p["id"] == policy_id for p in (await client.get("/patch-approval/policies", headers=op)).json())
    assert (await client.get(f"/patch-approval/policies/{policy_id}", headers=view)).status_code == 200
    # delete
    assert (await client.delete(f"/patch-approval/policies/{policy_id}", headers=op)).status_code == 204


@pytest.mark.asyncio
async def test_effective_resolution_prefers_most_specific(client):
    op = await auth(client)
    org_id, site_id, agent_id = await enroll(client, op)
    await seed_updates(agent_id, [update("KB111", "Updates")])

    await client.post("/patch-approval/policies", headers=op,
                      json={"name": "Global allow", "scope": "global",
                            "rules": [{"key": "all", "action": "approve", "match": {"classifications": ["Updates"]}}],
                            "default_action": "approve"})
    await client.post("/patch-approval/policies", headers=op,
                      json={"name": "Site deny", "scope": "site", "scope_id": site_id,
                            "rules": [{"key": "all", "action": "deny", "match": {"classifications": ["Updates"]}}],
                            "default_action": "deny"})

    effective = await client.get(f"/agents/{agent_id}/patch-approval/effective", headers=op)
    assert effective.status_code == 200
    body = effective.json()
    assert body["scope"] == "site"  # most specific wins
    assert body["decisions"][0]["decision"] == "deny"


@pytest.mark.asyncio
async def test_install_gate_denies_narrows_and_defers(client):
    op = await auth(client)
    _, site_id, agent_id = await enroll(client, op)
    await seed_updates(agent_id, [
        update("KB1001", "Definition Updates"),
        update("KB1002", "Security Updates", "Important", days_old=2),   # deferred (too new)
        update("KB1003", "Security Updates", "Important", days_old=30),  # deferral elapsed -> approve
        update("KB1004", "Updates", "Critical"),                         # approve by severity
    ])
    await client.post("/patch-approval/policies", headers=op, json={
        "name": "Baseline", "scope": "site", "scope_id": site_id, "default_action": "deny",
        "rules": [
            {"key": "block-defs", "action": "deny", "match": {"classifications": ["Definition Updates"]}},
            {"key": "defer-sec", "action": "defer", "defer_days": 7, "match": {"classifications": ["Security Updates"]}},
            {"key": "ok-critical", "action": "approve", "match": {"severities": ["Critical"]}},
        ],
    })

    # Explicit denied KB is refused, fail-closed.
    denied = await client.post(f"/agents/{agent_id}/commands", headers=op,
                               json={"kind": "install_updates", "payload": {"install_all": False, "kb_ids": ["KB1001"], "update_ids": []}})
    assert denied.status_code == 409
    assert denied.json()["detail"]["code"] == "patch_install_denied"

    # install_all narrows to the approved subset (KB1003 + KB1004).
    all_install = await client.post(f"/agents/{agent_id}/commands", headers=op,
                                    json={"kind": "install_updates", "payload": {"install_all": True, "kb_ids": [], "update_ids": []}})
    assert all_install.status_code == 200, all_install.text
    payload = all_install.json()["payload"]
    assert payload["install_all"] is False
    assert sorted(payload["kb_ids"]) == ["KB1003", "KB1004"]

    # A gated audit event was recorded.
    async with AsyncSessionLocal() as db:
        events = (await db.execute(select(AuditEvent).where(AuditEvent.action == "patch_install.gated"))).scalars().all()
        assert events and any(e.detail["outcome"] == "denied" for e in events)


@pytest.mark.asyncio
async def test_require_maintenance_window_recurring(client):
    op = await auth(client)
    _, site_id, agent_id = await enroll(client, op)
    await seed_updates(agent_id, [update("KB2001", "Updates", "Critical")])
    await client.post("/patch-approval/policies", headers=op, json={
        "name": "Windowed", "scope": "site", "scope_id": site_id, "default_action": "approve",
        "require_maintenance_window": True, "rules": [],
    })

    # No window -> blocked.
    blocked = await client.post(f"/agents/{agent_id}/commands", headers=op,
                                json={"kind": "install_updates", "payload": {"install_all": True, "kb_ids": [], "update_ids": []}})
    assert blocked.status_code == 409
    assert blocked.json()["detail"]["code"] == "patch_install_maintenance_window_required"

    # An always-open recurring window (every weekday, 00:00 for 24h) admits it.
    now = datetime.now(timezone.utc)
    await client.post("/monitoring/maintenance-windows", headers=op, json={
        "name": "Always", "scope": "site", "scope_id": site_id,
        "starts_at": (now - timedelta(days=1)).isoformat(),
        "ends_at": (now + timedelta(days=365)).isoformat(),
        "timezone": "UTC",
        "recurrence": {"days": [0, 1, 2, 3, 4, 5, 6], "start": "00:00", "duration_minutes": 1439},
    })
    allowed = await client.post(f"/agents/{agent_id}/commands", headers=op,
                                json={"kind": "install_updates", "payload": {"install_all": True, "kb_ids": [], "update_ids": []}})
    assert allowed.status_code == 200, allowed.text


@pytest.mark.asyncio
async def test_opt_in_no_policy_passes_through(client):
    op = await auth(client)
    _, _, agent_id = await enroll(client, op)
    await seed_updates(agent_id, [update("KB3001", "Updates")])
    # No policy exists -> install proceeds unchanged (install_all stays install_all).
    response = await client.post(f"/agents/{agent_id}/commands", headers=op,
                                 json={"kind": "install_updates", "payload": {"install_all": True, "kb_ids": [], "update_ids": []}})
    assert response.status_code == 200, response.text
    assert response.json()["payload"]["install_all"] is True


@pytest.mark.asyncio
async def test_reboot_evidence_injected_only_for_capable_agent(client):
    op = await auth(client)
    _, _, capable = await enroll(client, op, capabilities=["patch-reboot-v1"])
    _, _, legacy = await enroll(client, op)
    for agent in (capable, legacy):
        await seed_updates(agent, [update("KB5005001", "Updates", "Critical")])
    await client.post("/patch-approval/policies", headers=op, json={
        "name": "Reboot", "scope": "global", "default_action": "approve", "rules": [],
        "reboot_policy": "if_required", "reboot_delay_seconds": 120,
        "reboot_requires_no_user": True, "max_install_attempts": 3,
    })

    capable_cmd = await client.post(f"/agents/{capable}/commands", headers=op,
                                    json={"kind": "install_updates", "payload": {"install_all": True, "kb_ids": [], "update_ids": []}})
    assert capable_cmd.status_code == 200, capable_cmd.text
    payload = capable_cmd.json()["payload"]
    assert payload["max_attempts"] == 3
    assert payload["reboot"]["policy"] == "if_required"
    assert payload["reboot"]["delay_seconds"] == 120
    assert payload["reboot"]["requires_no_user"] is True

    # An agent without the capability gets no #53 payload extensions (mixed-version safe).
    legacy_cmd = await client.post(f"/agents/{legacy}/commands", headers=op,
                                   json={"kind": "install_updates", "payload": {"install_all": True, "kb_ids": [], "update_ids": []}})
    assert legacy_cmd.status_code == 200, legacy_cmd.text
    legacy_payload = legacy_cmd.json()["payload"]
    assert "reboot" not in legacy_payload and "max_attempts" not in legacy_payload

    async with AsyncSessionLocal() as db:
        authorized = (await db.execute(select(AuditEvent).where(AuditEvent.action == "patch_install.reboot_authorized"))).scalars().all()
        assert len(authorized) == 1 and authorized[0].detail["reboot_policy"] == "if_required"


@pytest.mark.asyncio
async def test_scheduler_applies_patch_gate(client):
    op = await auth(client)
    _, site_id, agent_id = await enroll(client, op)
    await seed_updates(agent_id, [
        update("KB5006001", "Definition Updates"),
        update("KB5006002", "Updates", "Critical"),
    ])
    await client.post("/patch-approval/policies", headers=op, json={
        "name": "Sched", "scope": "site", "scope_id": site_id, "default_action": "deny",
        "rules": [
            {"key": "defs", "action": "deny", "match": {"classifications": ["Definition Updates"]}},
            {"key": "crit", "action": "approve", "match": {"severities": ["Critical"]}},
        ],
    })
    now = datetime.now(timezone.utc)

    def install_task(target_id):
        return ScheduledTask(
            id=str(uuid4()), name="Nightly patch", enabled=True,
            target_type=ScheduleTargetType.agent, target_id=target_id,
            cron_expression="0 * * * *", timezone="UTC", kind=CommandKind.install_updates,
            payload={"install_all": True, "kb_ids": [], "update_ids": []},
            concurrency_policy=ScheduleConcurrencyPolicy.skip,
            misfire_policy=ScheduleMisfirePolicy.run_once,
            next_run_at=now - timedelta(minutes=5),
        )

    async with AsyncSessionLocal() as db:
        db.add(install_task(agent_id))
        await db.commit()
        await dispatch_scheduled_tasks_once(db, now=now)
        cmds = (await db.execute(select(Command).where(Command.kind == CommandKind.install_updates))).scalars().all()
        # The scheduled install was gated: narrowed to the approved Critical KB only.
        assert len(cmds) == 1
        assert cmds[0].payload["install_all"] is False
        assert cmds[0].payload["kb_ids"] == ["KB5006002"]


@pytest.mark.asyncio
async def test_scheduler_gate_blocks_outside_required_window(client):
    op = await auth(client)
    _, site_id, agent_id = await enroll(client, op)
    await seed_updates(agent_id, [update("KB5007001", "Updates", "Critical")])
    await client.post("/patch-approval/policies", headers=op, json={
        "name": "Windowed", "scope": "site", "scope_id": site_id, "default_action": "approve",
        "require_maintenance_window": True, "rules": [],
    })
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        db.add(ScheduledTask(
            id=str(uuid4()), name="Windowed patch", enabled=True,
            target_type=ScheduleTargetType.agent, target_id=agent_id,
            cron_expression="0 * * * *", timezone="UTC", kind=CommandKind.install_updates,
            payload={"install_all": True, "kb_ids": [], "update_ids": []},
            concurrency_policy=ScheduleConcurrencyPolicy.skip,
            misfire_policy=ScheduleMisfirePolicy.run_once,
            next_run_at=now - timedelta(minutes=5),
        ))
        await db.commit()
        await dispatch_scheduled_tasks_once(db, now=now)
        cmds = (await db.execute(select(Command).where(Command.kind == CommandKind.install_updates))).scalars().all()
        assert cmds == []  # blocked: no active maintenance window
