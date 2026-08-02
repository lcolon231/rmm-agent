# SPDX-License-Identifier: AGPL-3.0-only
"""Monitoring policy, evaluation, and check-result behavior (#41/#42)."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import pytest_asyncio

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_monitoring.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
from pydantic import ValidationError  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

from app.core import monitoring as monitoring_core  # noqa: E402
from app.core.command_envelope import COMMAND_ENVELOPE_V3  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    AuditEvent,
    CheckResult,
    CheckResultStatus,
    Operator,
    OperatorRole,
    ScriptExecutionScope,
)
from app.schemas.monitoring import MonitoringPolicyCreate  # noqa: E402


def _numeric_check(
    key: str,
    check_type: str = "cpu",
    *,
    warning: float = 80,
    critical: float = 95,
    enabled: bool = True,
    params: dict | None = None,
) -> dict:
    return {
        "key": key,
        "type": check_type,
        "enabled": enabled,
        "schedule": {"interval_seconds": 60},
        "threshold": {
            "op": "gte",
            "warning": warning,
            "critical": critical,
        },
        "params": params or {},
    }


def _reboot_check(key: str, *, enabled: bool = True) -> dict:
    return {
        "key": key,
        "type": "reboot_pending",
        "enabled": enabled,
        "schedule": {"interval_seconds": 300},
        "params": {},
    }


def _service_check(key: str, service_name: str = "Spooler") -> dict:
    return {
        "key": key,
        "type": "service",
        "enabled": True,
        "schedule": {"interval_seconds": 60},
        "hysteresis": {"raise_samples": 1, "clear_samples": 1},
        "params": {"service_name": service_name},
    }


def _offline_check(
    key: str, *, raise_samples: int = 1, clear_samples: int = 1
) -> dict:
    return {
        "key": key,
        "type": "offline",
        "enabled": True,
        "schedule": {"interval_seconds": 30},
        "threshold": {"op": "gte", "warning": 60, "critical": 120},
        "hysteresis": {
            "raise_samples": raise_samples,
            "clear_samples": clear_samples,
        },
        "params": {},
    }


@pytest_asyncio.fixture
async def operator_client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                Operator(
                    email="monitor@nodelink.test",
                    password_hash=hash_password("monitor-password"),
                    role=OperatorRole.operator,
                    script_execution_scope=ScriptExecutionScope.global_,
                ),
                Operator(
                    email="monitor-viewer@nodelink.test",
                    password_hash=hash_password("viewer-password"),
                    role=OperatorRole.readonly,
                ),
            ]
        )
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://t/api/v1"
    ) as client:
        login = await client.post(
            "/auth/login",
            json={
                "email": "monitor@nodelink.test",
                "password": "monitor-password",
            },
        )
        client.headers.update(
            {"Authorization": f"Bearer {login.json()['access_token']}"}
        )
        yield client
    await engine.dispose()


async def _enroll(client) -> tuple[str, str, str, str]:
    customer = (
        await client.post(
            "/clients", json={"name": f"Monitoring Clinic {uuid4().hex}"}
        )
    ).json()
    site = (
        await client.post(
            "/sites", json={"client_id": customer["id"], "name": "HQ"}
        )
    ).json()
    token = (
        await client.post("/enrollment-tokens", json={"site_id": site["id"]})
    ).json()
    enrollment = (
        await client.post(
            "/enroll",
            json={
                "enrollment_token": token["token"],
                "hostname": "MONITOR-PC",
                "os": "windows",
                "supported_command_envelope_versions": [COMMAND_ENVELOPE_V3],
            },
        )
    ).json()
    return customer["id"], site["id"], enrollment["agent_id"], enrollment["agent_token"]


async def _create_policy(
    client,
    *,
    name: str,
    scope: str,
    scope_id: str | None,
    checks: list[dict],
):
    response = await client.post(
        "/monitoring/policies",
        json={
            "name": name,
            "scope": scope,
            "scope_id": scope_id,
            "checks": checks,
            "change_note": f"Create {name}",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_policy_validation_is_fail_closed():
    base = {
        "name": "Default",
        "scope": "global",
        "scope_id": None,
    }
    with pytest.raises(ValidationError, match="greater than or equal to 30"):
        MonitoringPolicyCreate.model_validate(
            {**base, "checks": [{**_numeric_check("cpu"), "schedule": {"interval_seconds": 1}}]}
        )
    with pytest.raises(ValidationError, match="unique"):
        MonitoringPolicyCreate.model_validate(
            {**base, "checks": [_numeric_check("cpu"), _numeric_check("cpu")]}
        )
    with pytest.raises(ValidationError, match="critical must be >= warning"):
        MonitoringPolicyCreate.model_validate(
            {**base, "checks": [_numeric_check("cpu", warning=90, critical=70)]}
        )
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        MonitoringPolicyCreate.model_validate(
            {**base, "checks": [_numeric_check("cpu", params={"secret": True})]}
        )
    with pytest.raises(ValidationError, match="requires a scope_id"):
        MonitoringPolicyCreate.model_validate(
            {**base, "scope": "site", "checks": []}
        )
    with pytest.raises(ValidationError, match="must not include a scope_id"):
        MonitoringPolicyCreate.model_validate(
            {**base, "scope_id": "not-global", "checks": []}
        )


@pytest.mark.asyncio
async def test_policy_crud_revisioning_duplicate_names_and_audit(operator_client):
    created = await _create_policy(
        operator_client,
        name="Default Health",
        scope="global",
        scope_id=None,
        checks=[_numeric_check("cpu")],
    )
    assert created["current_version"] == 1
    assert created["check_count"] == 1

    duplicate = await operator_client.post(
        "/monitoring/policies",
        json={
            "name": "  default health  ",
            "scope": "global",
            "scope_id": None,
            "checks": [],
        },
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"]["code"] == "monitoring_policy_name_exists"

    revised = await operator_client.put(
        f"/monitoring/policies/{created['id']}",
        json={
            "enabled": False,
            "checks": [_numeric_check("cpu", warning=75), _reboot_check("reboot")],
            "change_note": "Tune thresholds without storing this prose",
        },
    )
    assert revised.status_code == 200, revised.text
    assert revised.json()["current_version"] == 2
    assert revised.json()["enabled"] is False
    assert revised.json()["check_count"] == 2

    revisions = await operator_client.get(
        f"/monitoring/policies/{created['id']}/revisions"
    )
    assert [row["version"] for row in revisions.json()] == [2, 1]
    detail = await operator_client.get(f"/monitoring/policies/{created['id']}")
    assert detail.status_code == 200
    assert len(detail.json()["revisions"]) == 2

    deleted = await operator_client.delete(f"/monitoring/policies/{created['id']}")
    assert deleted.status_code == 204
    assert (
        await operator_client.get(f"/monitoring/policies/{created['id']}")
    ).status_code == 404

    async with AsyncSessionLocal() as db:
        events = list(
            (
                await db.execute(
                    select(AuditEvent).where(
                        AuditEvent.action.like("monitoring_policy.%")
                    )
                )
            ).scalars().all()
        )
    by_action = {event.action: event.detail for event in events}
    assert {
        "monitoring_policy.created",
        "monitoring_policy.revised",
        "monitoring_policy.viewed",
        "monitoring_policy.deleted",
    } <= set(by_action)
    serialized = str(by_action)
    assert "Default Health" not in serialized
    assert "Tune thresholds" not in serialized
    assert "name_sha256" in by_action["monitoring_policy.created"]
    assert "change_note_sha256" in by_action["monitoring_policy.revised"]


@pytest.mark.asyncio
async def test_effective_policy_merges_all_scope_levels(operator_client):
    client_id, site_id, agent_id, _ = await _enroll(operator_client)
    await _create_policy(
        operator_client,
        name="Global",
        scope="global",
        scope_id=None,
        checks=[_numeric_check("cpu"), _numeric_check("memory", "memory")],
    )
    await _create_policy(
        operator_client,
        name="Client override",
        scope="client",
        scope_id=client_id,
        checks=[_numeric_check("cpu", warning=70)],
    )
    await _create_policy(
        operator_client,
        name="Site override",
        scope="site",
        scope_id=site_id,
        checks=[
            _numeric_check("memory", "memory", enabled=False),
            _numeric_check("disk", "disk", params={"mount_point": "C:"}),
        ],
    )
    await _create_policy(
        operator_client,
        name="Agent override",
        scope="agent",
        scope_id=agent_id,
        checks=[
            _numeric_check(
                "disk", "disk", warning=88, critical=97, params={"mount_point": "C:"}
            ),
            _numeric_check("uptime", "uptime", warning=600, critical=3000),
        ],
    )

    response = await operator_client.get(
        f"/agents/{agent_id}/monitoring/effective-policy"
    )
    assert response.status_code == 200, response.text
    checks = {item["definition"]["key"]: item for item in response.json()["checks"]}
    assert set(checks) == {"cpu", "disk", "uptime"}
    assert checks["cpu"]["source_scope"] == "client"
    assert checks["cpu"]["definition"]["threshold"]["warning"] == 70
    assert checks["disk"]["source_scope"] == "agent"
    assert checks["uptime"]["source_scope"] == "agent"


@pytest.mark.asyncio
async def test_windows_authz_scope_targets_and_unknown_ids(operator_client):
    client_id, _, _, _ = await _enroll(operator_client)
    login = await operator_client.post(
        "/auth/login",
        json={
            "email": "monitor-viewer@nodelink.test",
            "password": "viewer-password",
        },
    )
    readonly = {"Authorization": f"Bearer {login.json()['access_token']}"}
    payload = {
        "name": "Window",
        "scope": "client",
        "scope_id": client_id,
        "starts_at": "2026-08-02T01:00:00+00:00",
        "ends_at": "2026-08-02T03:00:00+00:00",
    }
    assert (
        await operator_client.post(
            "/monitoring/maintenance-windows", json=payload, headers=readonly
        )
    ).status_code == 403

    invalid_time = await operator_client.post(
        "/monitoring/maintenance-windows",
        json={**payload, "ends_at": "2026-08-02T00:00:00+00:00"},
    )
    assert invalid_time.status_code == 422
    missing_target = await operator_client.post(
        "/monitoring/policies",
        json={
            "name": "Missing target",
            "scope": "client",
            "scope_id": "missing-client",
            "checks": [],
        },
    )
    assert missing_target.status_code == 404

    created = await operator_client.post(
        "/monitoring/maintenance-windows", json=payload
    )
    assert created.status_code == 201, created.text
    assert (
        await operator_client.get(
            "/monitoring/maintenance-windows", headers=readonly
        )
    ).status_code == 200
    assert (
        await operator_client.delete(
            f"/monitoring/maintenance-windows/{created.json()['id']}"
        )
    ).status_code == 204
    assert (
        await operator_client.delete("/monitoring/maintenance-windows/missing")
    ).status_code == 404
    assert (
        await operator_client.get("/monitoring/policies/missing")
    ).status_code == 404

    unauthenticated = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t/api/v1"
    )
    async with unauthenticated:
        assert (
            await unauthenticated.get("/monitoring/policies")
        ).status_code == 401

    async with AsyncSessionLocal() as db:
        audit_details = list(
            (
                await db.execute(
                    select(AuditEvent.detail).where(
                        AuditEvent.action.like("maintenance_window.%")
                    )
                )
            ).scalars().all()
        )
    assert len(audit_details) == 2
    assert all("name_sha256" in detail and "name" not in detail for detail in audit_details)


@pytest.mark.asyncio
async def test_check_result_read_contract_and_per_key_retention(operator_client):
    _, _, agent_id, _ = await _enroll(operator_client)
    async with AsyncSessionLocal() as db:
        for index in range(4):
            await monitoring_core.record_check_result(
                db,
                agent_id=agent_id,
                check_key="cpu",
                status=CheckResultStatus.ok,
                value=float(index),
                detail={"sample": index},
                evaluated_at=datetime.now(timezone.utc) + timedelta(seconds=index),
            )
        await monitoring_core.record_check_result(
            db,
            agent_id=agent_id,
            check_key="memory",
            status=CheckResultStatus.warning,
            value=91.0,
        )
        await db.commit()
        assert await monitoring_core.prune_check_results(db, keep=2) == 2
        await db.commit()
        cpu_count = (
            await db.execute(
                select(func.count())
                .select_from(CheckResult)
                .where(
                    CheckResult.agent_id == agent_id,
                    CheckResult.check_key == "cpu",
                )
            )
        ).scalar_one()
        memory_count = (
            await db.execute(
                select(func.count())
                .select_from(CheckResult)
                .where(
                    CheckResult.agent_id == agent_id,
                    CheckResult.check_key == "memory",
                )
            )
        ).scalar_one()
    assert cpu_count == 2
    assert memory_count == 1

    response = await operator_client.get(
        f"/agents/{agent_id}/monitoring/results?check_key=cpu"
    )
    assert response.status_code == 200, response.text
    assert response.json()["agent_id"] == agent_id
    assert len(response.json()["items"]) == 2
    assert all(item["check_key"] == "cpu" for item in response.json()["items"])
    assert (
        await operator_client.get("/agents/missing/monitoring/results")
    ).status_code == 404


@pytest.mark.asyncio
async def test_check_result_seam_rejects_unbounded_or_ambiguous_input(operator_client):
    _, _, agent_id, _ = await _enroll(operator_client)
    async with AsyncSessionLocal() as db:
        with pytest.raises(ValueError, match="lowercase slug"):
            await monitoring_core.record_check_result(
                db,
                agent_id=agent_id,
                check_key="CPU usage",
                status=CheckResultStatus.ok,
            )
        with pytest.raises(ValueError, match="timezone"):
            await monitoring_core.record_check_result(
                db,
                agent_id=agent_id,
                check_key="cpu",
                status=CheckResultStatus.ok,
                evaluated_at=datetime(2026, 8, 1, 12, 0, 0),
            )
        with pytest.raises(ValueError, match="exceeds"):
            await monitoring_core.record_check_result(
                db,
                agent_id=agent_id,
                check_key="cpu",
                status=CheckResultStatus.ok,
                detail={"message": "x" * 20_000},
            )


@pytest.mark.asyncio
async def test_agent_receives_revision_pinned_checks_and_ingests_idempotently(
    operator_client,
):
    _, _, agent_id, agent_token = await _enroll(operator_client)
    policy = await _create_policy(
        operator_client,
        name="Agent evaluation",
        scope="global",
        scope_id=None,
        checks=[
            _numeric_check("cpu"),
            _service_check("spooler"),
            _offline_check("offline"),
        ],
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://t/api/v1",
        headers={"Authorization": f"Bearer {agent_token}"},
    ) as agent_client:
        heartbeat = await agent_client.post(
            "/heartbeat",
            json={
                "cpu_percent": 85,
                "mem_percent": 50,
                "disk_percent": 40,
                "uptime_seconds": 1000,
                "supported_command_envelope_versions": [COMMAND_ENVELOPE_V3],
            },
        )
        assert heartbeat.status_code == 200, heartbeat.text
        assignments = {
            item["definition"]["key"]: item
            for item in heartbeat.json()["monitoring_checks"]
        }
        assert set(assignments) == {"cpu", "spooler"}
        assert assignments["cpu"]["policy_id"] == policy["id"]
        assert assignments["cpu"]["policy_revision_id"]

        evaluated_at = datetime.now(timezone.utc).isoformat()
        results = [
            {
                "id": "a" * 32,
                "policy_id": policy["id"],
                "policy_revision_id": assignments["cpu"]["policy_revision_id"],
                "check_key": "cpu",
                "status": "warning",
                "value": 85,
                "detail": {"reason": "threshold_evaluated"},
                "evaluated_at": evaluated_at,
            },
            {
                "id": "b" * 32,
                "policy_id": policy["id"],
                "policy_revision_id": assignments["spooler"]["policy_revision_id"],
                "check_key": "spooler",
                "status": "ok",
                "value": 1,
                "detail": {"reason": "service_running"},
                "evaluated_at": evaluated_at,
            },
        ]
        accepted = await agent_client.post(
            "/agents/me/monitoring/results", json={"results": results}
        )
        assert accepted.status_code == 200, accepted.text
        assert accepted.json() == {"ok": True, "accepted": 2, "duplicates": 0}

        duplicate = await agent_client.post(
            "/agents/me/monitoring/results", json={"results": results}
        )
        assert duplicate.status_code == 200
        assert duplicate.json()["duplicates"] == 2

        conflicting_retry = await agent_client.post(
            "/agents/me/monitoring/results",
            json={"results": [dict(results[0], status="critical")]},
        )
        assert conflicting_retry.status_code == 409
        assert conflicting_retry.json()["detail"]["code"] == "monitoring_result_id_conflict"

        superseded = dict(results[0], id="c" * 32, policy_revision_id=str(uuid4()))
        rejected = await agent_client.post(
            "/agents/me/monitoring/results", json={"results": [superseded]}
        )
        assert rejected.status_code == 409
        assert rejected.json()["detail"]["code"] == "monitoring_policy_superseded"

        stale = dict(
            results[0],
            id="d" * 32,
            evaluated_at=(datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(),
        )
        rejected = await agent_client.post(
            "/agents/me/monitoring/results", json={"results": [stale]}
        )
        assert rejected.status_code == 422
        assert rejected.json()["detail"]["code"] == "monitoring_result_stale"

    stored = await operator_client.get(
        f"/agents/{agent_id}/monitoring/results"
    )
    assert stored.status_code == 200
    assert {item["check_key"] for item in stored.json()["items"]} == {
        "cpu",
        "spooler",
    }


@pytest.mark.asyncio
async def test_offline_check_cadence_hysteresis_and_recovery(operator_client):
    _, _, agent_id, _ = await _enroll(operator_client)
    await _create_policy(
        operator_client,
        name="Offline evaluation",
        scope="agent",
        scope_id=agent_id,
        checks=[_offline_check("offline", raise_samples=2, clear_samples=2)],
    )
    start = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        agent = await db.get(Agent, agent_id)
        agent.last_seen_at = start - timedelta(seconds=180)

        assert await monitoring_core.evaluate_offline_checks(db, agent, start) == 1
        await db.flush()
        first = await db.scalar(
            select(CheckResult).where(CheckResult.agent_id == agent_id)
        )
        assert first.status == CheckResultStatus.unknown
        assert first.detail["raw_status"] == "critical"
        assert first.detail["hysteresis"]["pending_count"] == 1

        assert (
            await monitoring_core.evaluate_offline_checks(
                db, agent, start + timedelta(seconds=10)
            )
            == 0
        )
        assert (
            await monitoring_core.evaluate_offline_checks(
                db, agent, start + timedelta(seconds=31)
            )
            == 1
        )
        agent.last_seen_at = start + timedelta(seconds=31)
        assert (
            await monitoring_core.evaluate_offline_checks(
                db, agent, start + timedelta(seconds=62)
            )
            == 1
        )
        agent.last_seen_at = start + timedelta(seconds=62)
        assert (
            await monitoring_core.evaluate_offline_checks(
                db, agent, start + timedelta(seconds=93)
            )
            == 1
        )
        await db.commit()

        history = list(
            (
                await db.execute(
                    select(CheckResult)
                    .where(CheckResult.agent_id == agent_id)
                    .order_by(CheckResult.evaluated_at)
                )
            ).scalars().all()
        )
    assert [row.status for row in history] == [
        CheckResultStatus.unknown,
        CheckResultStatus.critical,
        CheckResultStatus.critical,
        CheckResultStatus.ok,
    ]
    assert history[-1].detail["reason"] == "heartbeat_within_threshold"
