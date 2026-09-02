# SPDX-License-Identifier: AGPL-3.0-only
"""Patch-age monitoring policy and evaluator behavior (issue #229)."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import event, func, select

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_patch_age_checks.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

from app.core import monitoring as monitoring_core  # noqa: E402
from app.core.database import AsyncSessionLocal, engine  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    AgentInventorySnapshot,
    Alert,
    AlertEvent,
    AlertEventType,
    AlertState,
    CheckResult,
    CheckResultStatus,
)
from app.schemas.monitoring import MonitoringPolicyCreate  # noqa: E402
from tests.test_monitoring import (  # noqa: E402
    _create_policy,
    _enroll,
    operator_client,
)


def _check(
    *,
    check_type: str = "patch_age",
    op: str = "gt",
    interval_seconds: int = 3600,
    params: dict | None = None,
) -> dict:
    return {
        "key": "patch-age",
        "type": check_type,
        "enabled": True,
        "schedule": {"interval_seconds": interval_seconds},
        "threshold": {"op": op, "warning": 30, "critical": 60},
        "params": params or {},
    }


def _policy(check: dict) -> dict:
    return {
        "name": "Patch age",
        "scope": "global",
        "scope_id": None,
        "checks": [check],
    }


async def _agent_policy(
    client,
    *,
    raise_samples: int = 1,
    clear_samples: int = 1,
) -> tuple[str, dict]:
    _, _, agent_id, _ = await _enroll(client)
    check = _check()
    check["hysteresis"] = {
        "raise_samples": raise_samples,
        "clear_samples": clear_samples,
    }
    policy = await _create_policy(
        client,
        name=f"Patch age {uuid4().hex}",
        scope="agent",
        scope_id=agent_id,
        checks=[check],
    )
    return agent_id, policy


def _snapshot(
    agent_id: str,
    *,
    received_at: datetime,
    status: str = "ok",
    installed: list[dict] | None = None,
) -> AgentInventorySnapshot:
    payload = {
        "scanned_at": received_at.isoformat(),
        "missing": [],
        "installed": installed or [],
    }
    return AgentInventorySnapshot(
        agent_id=agent_id,
        section="windows_updates",
        status=status,
        schema_version=1,
        content_hash=uuid4().hex * 2,
        byte_size=1,
        payload=payload,
        collected_at=received_at,
        received_at=received_at,
    )


def test_patch_age_accepts_rising_threshold_without_params():
    policy = MonitoringPolicyCreate.model_validate(_policy(_check()))

    assert policy.checks[0].type.value == "patch_age"
    assert policy.checks[0].schedule.interval_seconds == 3600


@pytest.mark.parametrize("op", ["lt", "lte"])
def test_patch_age_rejects_falling_thresholds(op: str):
    with pytest.raises(ValidationError, match="rising threshold"):
        MonitoringPolicyCreate.model_validate(_policy(_check(op=op)))


def test_patch_age_rejects_params():
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        MonitoringPolicyCreate.model_validate(
            _policy(_check(params={"source": "windows_updates"}))
        )


def test_patch_age_has_a_type_specific_hourly_cadence_floor():
    with pytest.raises(ValidationError, match="at least 3600 seconds"):
        MonitoringPolicyCreate.model_validate(
            _policy(_check(interval_seconds=3599))
        )

    cpu = _check(check_type="cpu", interval_seconds=30)
    cpu["key"] = "cpu"
    MonitoringPolicyCreate.model_validate(_policy(cpu))


@pytest.mark.asyncio
async def test_patch_age_opens_and_automatically_recovers_alert(operator_client):
    agent_id, policy = await _agent_policy(operator_client)
    start = datetime(2026, 9, 2, 12, tzinfo=timezone.utc)

    async with AsyncSessionLocal() as db:
        agent = await db.get(Agent, agent_id)
        db.add(
            _snapshot(
                agent_id,
                received_at=start,
                installed=[
                    {
                        "kb_id": "KB-OLD",
                        "installed_on": (start - timedelta(days=75)).isoformat(),
                    }
                ],
            )
        )
        await db.flush()
        assert await monitoring_core.evaluate_patch_age_checks(db, agent, start) == 1
        await db.flush()

        result = await db.scalar(select(CheckResult).where(CheckResult.agent_id == agent_id))
        alert = await db.scalar(select(Alert).where(Alert.agent_id == agent_id))
        assert result.status == CheckResultStatus.critical
        assert result.value == pytest.approx(75.0)
        assert alert.state == AlertState.open

        recovered_at = start + timedelta(hours=1, seconds=1)
        db.add(
            _snapshot(
                agent_id,
                received_at=recovered_at,
                installed=[
                    {"kb_id": "KB-NEW", "installed_on": recovered_at.isoformat()}
                ],
            )
        )
        await db.flush()
        assert (
            await monitoring_core.evaluate_patch_age_checks(db, agent, recovered_at)
            == 1
        )
        await db.commit()

        await db.refresh(alert)
        events = list(
            (
                await db.execute(
                    select(AlertEvent).where(AlertEvent.alert_id == alert.id)
                )
            ).scalars()
        )
        assert alert.state == AlertState.resolved
        assert alert.resolution_reason == "automatic_recovery"
        assert AlertEventType.automatic_recovery in {event.event_type for event in events}


@pytest.mark.asyncio
async def test_patch_age_without_inventory_is_unknown_and_opens_no_alert(
    operator_client,
):
    agent_id, _ = await _agent_policy(operator_client)
    at = datetime(2026, 9, 2, 12, tzinfo=timezone.utc)

    async with AsyncSessionLocal() as db:
        agent = await db.get(Agent, agent_id)
        assert await monitoring_core.evaluate_patch_age_checks(db, agent, at) == 1
        await db.commit()

        result = await db.scalar(select(CheckResult).where(CheckResult.agent_id == agent_id))
        alert = await db.scalar(select(Alert).where(Alert.agent_id == agent_id))
        assert result.status == CheckResultStatus.unknown
        assert result.detail["reason"] == "no_update_inventory"
        assert alert is None


@pytest.mark.parametrize(
    ("status", "installed", "expected_reason"),
    [
        (
            "error",
            [{"installed_on": "2026-08-01T00:00:00Z"}],
            "update_scan_unusable",
        ),
        ("ok", [], "no_installed_updates"),
        ("partial", [{"kb_id": "KB-NULL", "installed_on": None}], "no_install_timestamps"),
        (
            "ok",
            [{"installed_on": "2026-09-02T14:00:00Z"}],
            "install_timestamp_in_future",
        ),
    ],
)
@pytest.mark.asyncio
async def test_patch_age_reports_specific_unknown_reasons_without_alerting(
    operator_client,
    status: str,
    installed: list[dict],
    expected_reason: str,
):
    agent_id, _ = await _agent_policy(operator_client)
    at = datetime(2026, 9, 2, 12, tzinfo=timezone.utc)

    async with AsyncSessionLocal() as db:
        agent = await db.get(Agent, agent_id)
        db.add(
            _snapshot(
                agent_id,
                received_at=at,
                status=status,
                installed=installed,
            )
        )
        await db.flush()
        assert await monitoring_core.evaluate_patch_age_checks(db, agent, at) == 1
        await db.commit()

        result = await db.scalar(select(CheckResult).where(CheckResult.agent_id == agent_id))
        alert = await db.scalar(select(Alert).where(Alert.agent_id == agent_id))
        assert result.status == CheckResultStatus.unknown
        assert result.detail["reason"] == expected_reason
        assert alert is None


@pytest.mark.asyncio
async def test_patch_age_uses_newest_non_null_install_and_clamps_small_skew(
    operator_client,
):
    agent_id, _ = await _agent_policy(operator_client)
    at = datetime(2026, 9, 2, 12, tzinfo=timezone.utc)

    async with AsyncSessionLocal() as db:
        agent = await db.get(Agent, agent_id)
        db.add(
            _snapshot(
                agent_id,
                received_at=at,
                installed=[
                    {"kb_id": "KB-NULL", "installed_on": None},
                    {
                        "kb_id": "KB-OLD",
                        "installed_on": (at - timedelta(days=90)).isoformat(),
                    },
                    {
                        "kb_id": "KB-NEWEST",
                        "installed_on": (at + timedelta(minutes=2)).isoformat(),
                    },
                ],
            )
        )
        await db.flush()
        assert await monitoring_core.evaluate_patch_age_checks(db, agent, at) == 1
        await db.commit()

        result = await db.scalar(select(CheckResult).where(CheckResult.agent_id == agent_id))
        assert result.status == CheckResultStatus.ok
        assert result.value == 0
        assert result.detail["newest_kb_id"] == "KB-NEWEST"
        assert result.detail["installed_count"] == 3


@pytest.mark.asyncio
async def test_patch_age_not_due_performs_no_inventory_read(operator_client):
    agent_id, _ = await _agent_policy(operator_client)
    at = datetime(2026, 9, 2, 12, tzinfo=timezone.utc)

    async with AsyncSessionLocal() as db:
        agent = await db.get(Agent, agent_id)
        db.add(
            _snapshot(
                agent_id,
                received_at=at,
                installed=[
                    {"installed_on": (at - timedelta(days=10)).isoformat()}
                ],
            )
        )
        await db.flush()
        assert await monitoring_core.evaluate_patch_age_checks(db, agent, at) == 1

        inventory_queries: list[str] = []

        def capture_inventory_query(conn, cursor, statement, parameters, context, executemany):
            if "agent_inventory_snapshots" in statement:
                inventory_queries.append(statement)

        event.listen(engine.sync_engine, "before_cursor_execute", capture_inventory_query)
        try:
            assert (
                await monitoring_core.evaluate_patch_age_checks(
                    db, agent, at + timedelta(minutes=30)
                )
                == 0
            )
        finally:
            event.remove(engine.sync_engine, "before_cursor_execute", capture_inventory_query)

        assert inventory_queries == []
        assert (
            await db.scalar(
                select(func.count()).select_from(CheckResult).where(
                    CheckResult.agent_id == agent_id
                )
            )
            == 1
        )


@pytest.mark.asyncio
async def test_patch_age_revision_boundary_resets_due_time(operator_client):
    agent_id, policy = await _agent_policy(operator_client)
    at = datetime(2026, 9, 2, 12, tzinfo=timezone.utc)

    async with AsyncSessionLocal() as db:
        agent = await db.get(Agent, agent_id)
        db.add(
            _snapshot(
                agent_id,
                received_at=at,
                installed=[
                    {"installed_on": (at - timedelta(days=10)).isoformat()}
                ],
            )
        )
        await db.flush()
        assert await monitoring_core.evaluate_patch_age_checks(db, agent, at) == 1
        await db.commit()

    revised_check = _check()
    revised_check["threshold"] = {"op": "gt", "warning": 20, "critical": 40}
    revised = await operator_client.put(
        f"/monitoring/policies/{policy['id']}",
        json={"checks": [revised_check], "change_note": "Tune patch age"},
    )
    assert revised.status_code == 200, revised.text

    async with AsyncSessionLocal() as db:
        agent = await db.get(Agent, agent_id)
        assert (
            await monitoring_core.evaluate_patch_age_checks(
                db, agent, at + timedelta(minutes=1)
            )
            == 1
        )
        assert (
            await db.scalar(
                select(func.count()).select_from(CheckResult).where(
                    CheckResult.agent_id == agent_id
                )
            )
            == 2
        )


@pytest.mark.parametrize(
    ("age_days", "expected_status"),
    [
        (30, CheckResultStatus.ok),
        (31, CheckResultStatus.warning),
        (60, CheckResultStatus.warning),
        (61, CheckResultStatus.critical),
    ],
)
@pytest.mark.asyncio
async def test_patch_age_classifies_rising_threshold_bounds(
    operator_client,
    age_days: int,
    expected_status: CheckResultStatus,
):
    agent_id, _ = await _agent_policy(operator_client)
    at = datetime(2026, 9, 2, 12, tzinfo=timezone.utc)

    async with AsyncSessionLocal() as db:
        agent = await db.get(Agent, agent_id)
        db.add(
            _snapshot(
                agent_id,
                received_at=at,
                installed=[
                    {"installed_on": (at - timedelta(days=age_days)).isoformat()}
                ],
            )
        )
        await db.flush()
        assert await monitoring_core.evaluate_patch_age_checks(db, agent, at) == 1
        await db.commit()

        result = await db.scalar(select(CheckResult).where(CheckResult.agent_id == agent_id))
        assert result.status == expected_status


@pytest.mark.asyncio
async def test_patch_age_hysteresis_debounces_breach_and_recovery(operator_client):
    agent_id, _ = await _agent_policy(
        operator_client, raise_samples=2, clear_samples=2
    )
    start = datetime(2026, 9, 2, 12, tzinfo=timezone.utc)

    async with AsyncSessionLocal() as db:
        agent = await db.get(Agent, agent_id)
        db.add(
            _snapshot(
                agent_id,
                received_at=start,
                installed=[
                    {"installed_on": (start - timedelta(days=75)).isoformat()}
                ],
            )
        )
        await db.flush()
        assert await monitoring_core.evaluate_patch_age_checks(db, agent, start) == 1
        assert (
            await monitoring_core.evaluate_patch_age_checks(
                db, agent, start + timedelta(hours=1, seconds=1)
            )
            == 1
        )

        recovered_at = start + timedelta(hours=2, seconds=2)
        db.add(
            _snapshot(
                agent_id,
                received_at=recovered_at,
                installed=[{"installed_on": recovered_at.isoformat()}],
            )
        )
        await db.flush()
        assert (
            await monitoring_core.evaluate_patch_age_checks(db, agent, recovered_at)
            == 1
        )
        assert (
            await monitoring_core.evaluate_patch_age_checks(
                db, agent, start + timedelta(hours=3, seconds=3)
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
            ).scalars()
        )
        alert = await db.scalar(select(Alert).where(Alert.agent_id == agent_id))
        assert [result.status for result in history] == [
            CheckResultStatus.unknown,
            CheckResultStatus.critical,
            CheckResultStatus.critical,
            CheckResultStatus.ok,
        ]
        assert history[0].detail["hysteresis"]["pending_count"] == 1
        assert history[2].detail["hysteresis"]["pending_count"] == 1
        assert alert.state == AlertState.resolved
        assert alert.resolution_reason == "automatic_recovery"
