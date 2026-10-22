# SPDX-License-Identifier: AGPL-3.0-only
"""Refusal branches of the monitoring policy, window, alert, and email-delivery
routes (#284): configured limits, unknown ids, invalid alert/delivery states."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import pytest_asyncio

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_monitoring_refusals.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402

from app.core.command_envelope import COMMAND_ENVELOPE_V3  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    Alert,
    AlertEmailDelivery,
    AlertEventType,
    AlertState,
    CheckResultStatus,
    EmailDeliveryStatus,
    Operator,
    OperatorRole,
)

NOW = datetime(2026, 8, 4, 15, 30, tzinfo=timezone.utc)
DISABLED_OPERATOR_ID = "disabled-operator-0001"


def _check(key: str = "cpu", interval_seconds: int = 60) -> dict:
    return {
        "key": key,
        "type": "cpu",
        "enabled": True,
        "schedule": {"interval_seconds": interval_seconds},
        "threshold": {"op": "gte", "warning": 80, "critical": 95},
        "params": {},
    }


def _policy(name: str = "Baseline", checks: list[dict] | None = None) -> dict:
    return {
        "name": name,
        "scope": "global",
        "scope_id": None,
        "checks": checks if checks is not None else [_check()],
    }


def _window() -> dict:
    return {
        "name": "Patch night",
        "scope": "global",
        "scope_id": None,
        "starts_at": NOW.isoformat(),
        "ends_at": (NOW + timedelta(hours=2)).isoformat(),
    }


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                Operator(
                    email="refusals@nodelink.test",
                    password_hash=hash_password("refusals-password"),
                    role=OperatorRole.operator,
                ),
                Operator(
                    id=DISABLED_OPERATOR_ID,
                    email="disabled@nodelink.test",
                    password_hash=hash_password("disabled-password"),
                    role=OperatorRole.operator,
                    disabled=True,
                ),
            ]
        )
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://t/api/v1"
    ) as http:
        login = await http.post(
            "/auth/login",
            json={"email": "refusals@nodelink.test", "password": "refusals-password"},
        )
        http.headers["Authorization"] = f"Bearer {login.json()['access_token']}"
        yield http
    await engine.dispose()


async def _enroll(http) -> str:
    customer = (
        await http.post("/clients", json={"name": f"Refusal Clinic {uuid4().hex}"})
    ).json()
    site = (
        await http.post("/sites", json={"client_id": customer["id"], "name": "HQ"})
    ).json()
    token = (
        await http.post("/enrollment-tokens", json={"site_id": site["id"]})
    ).json()
    enrollment = (
        await http.post(
            "/enroll",
            json={
                "enrollment_token": token["token"],
                "hostname": "REFUSAL-PC",
                "os": "windows",
                "supported_command_envelope_versions": [COMMAND_ENVELOPE_V3],
            },
        )
    ).json()
    return enrollment["agent_id"]


async def _seed_alert(agent_id: str, state: AlertState) -> str:
    alert = Alert(
        id=str(uuid4()), agent_id=agent_id, policy_id=str(uuid4()),
        policy_revision_id=str(uuid4()), check_key="cpu", state=state,
        last_result_status=CheckResultStatus.warning, occurrence_count=1,
        total_occurrence_count=1, generation=1, version=1,
    )
    async with AsyncSessionLocal() as db:
        db.add(alert)
        await db.commit()
    return alert.id


@pytest.mark.parametrize(
    ("setting", "value", "interval_seconds", "code"),
    [
        ("monitoring_max_checks_per_policy", 0, 60,
         "monitoring_policy_check_limit_exceeded"),
        ("monitoring_check_interval_min_seconds", 120, 60,
         "monitoring_check_interval_out_of_bounds"),
        ("monitoring_check_interval_max_seconds", 60, 120,
         "monitoring_check_interval_out_of_bounds"),
    ],
)
async def test_policy_check_bounds_refuse_create_and_revise(
    client, monkeypatch, setting, value, interval_seconds, code
):
    existing = await client.post("/monitoring/policies", json=_policy())
    assert existing.status_code == 201, existing.text
    monkeypatch.setattr(settings, setting, value)
    checks = [_check(interval_seconds=interval_seconds)]

    created = await client.post(
        "/monitoring/policies", json=_policy("Second", checks)
    )
    revised = await client.put(
        f"/monitoring/policies/{existing.json()['id']}", json={"checks": checks}
    )

    for response in (created, revised):
        assert response.status_code == 422
        assert response.json()["detail"] == {"code": code}


@pytest.mark.parametrize(
    ("setting", "path", "body", "code"),
    [
        ("monitoring_max_policies", "/monitoring/policies", _policy(),
         "monitoring_policy_limit_reached"),
        ("monitoring_max_maintenance_windows", "/monitoring/maintenance-windows",
         _window(), "maintenance_window_limit_reached"),
    ],
)
async def test_create_refuses_when_deployment_limit_reached(
    client, monkeypatch, setting, path, body, code
):
    monkeypatch.setattr(settings, setting, 0)

    response = await client.post(path, json=body)

    assert response.status_code == 409
    assert response.json()["detail"] == {"code": code}


_ALERT_ACTION = {"request_id": "refusal-request-0001", "expected_version": 1}


@pytest.mark.parametrize(
    ("method", "path", "body", "detail"),
    [
        ("PUT", "/monitoring/policies/missing", {"checks": [_check()]},
         "Monitoring policy not found"),
        ("DELETE", "/monitoring/policies/missing", None,
         "Monitoring policy not found"),
        ("GET", "/monitoring/policies/missing/revisions", None,
         "Monitoring policy not found"),
        ("GET", "/agents/missing/monitoring/effective-policy", None,
         "Agent not found"),
        ("POST", "/monitoring/alerts/missing/acknowledge", _ALERT_ACTION,
         "Monitoring alert not found"),
        ("GET", "/monitoring/alerts/missing/email-deliveries", None,
         "Monitoring alert not found"),
        ("POST", "/monitoring/email-deliveries/missing/retry",
         {"request_id": "refusal-request-0001"}, "Email delivery not found"),
    ],
)
async def test_unknown_ids_are_404(client, method, path, body, detail):
    response = await client.request(method, path, json=body)

    assert response.status_code == 404
    assert response.json()["detail"] == detail


async def test_alert_whose_agent_is_gone_is_404(client):
    alert_id = await _seed_alert(str(uuid4()), AlertState.open)

    response = await client.post(
        f"/monitoring/alerts/{alert_id}/acknowledge", json=_ALERT_ACTION
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Monitoring alert not found"


@pytest.mark.parametrize(
    ("action", "state", "extra", "code"),
    [
        ("acknowledge", AlertState.acknowledged, {},
         "alert_acknowledge_invalid_state"),
        ("acknowledge", AlertState.resolved, {},
         "alert_acknowledge_invalid_state"),
        ("resolve", AlertState.resolved, {"comment": "Already fixed"},
         "alert_resolve_invalid_state"),
    ],
)
async def test_alert_action_refuses_invalid_state(client, action, state, extra, code):
    alert_id = await _seed_alert(await _enroll(client), state)

    response = await client.post(
        f"/monitoring/alerts/{alert_id}/{action}", json={**_ALERT_ACTION, **extra}
    )

    assert response.status_code == 409
    assert response.json()["detail"] == {"code": code, "state": state.value}


@pytest.mark.parametrize("assignee_id", ["missing-operator", DISABLED_OPERATOR_ID])
async def test_alert_assign_refuses_unavailable_assignee(client, assignee_id):
    alert_id = await _seed_alert(await _enroll(client), AlertState.open)

    response = await client.post(
        f"/monitoring/alerts/{alert_id}/assign",
        json={**_ALERT_ACTION, "assigned_to_operator_id": assignee_id},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == {"code": "alert_assignee_unavailable"}


@pytest.mark.parametrize(
    ("delivery_status", "attempt_count", "detail"),
    [
        (EmailDeliveryStatus.pending, 0,
         {"code": "email_delivery_retry_invalid_state", "status": "pending"}),
        (EmailDeliveryStatus.sent, 1,
         {"code": "email_delivery_retry_invalid_state", "status": "sent"}),
        (EmailDeliveryStatus.failed, 20,
         {"code": "email_delivery_retry_limit_reached"}),
    ],
)
async def test_email_delivery_retry_refusals(
    client, delivery_status, attempt_count, detail
):
    delivery = AlertEmailDelivery(
        id=str(uuid4()), alert_id=str(uuid4()), alert_event_id=str(uuid4()),
        generation=1, event_type=AlertEventType.opened,
        recipient="first@example.test",
        subject="NodeLink alert opened: cpu", text_body="Alert opened",
        html_body="<h2>Alert opened</h2>", status=delivery_status,
        attempt_count=attempt_count, max_attempts=20, next_attempt_at=NOW,
        created_at=NOW, updated_at=NOW,
    )
    async with AsyncSessionLocal() as db:
        db.add(delivery)
        await db.commit()

    response = await client.post(
        f"/monitoring/email-deliveries/{delivery.id}/retry",
        json={"request_id": "refusal-request-0001"},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == detail


async def test_duplicate_name_missed_by_precheck_is_409_not_500(client):
    # Regression: casefold() ("équipe") and SQLite lower() ("Équipe") disagree,
    # so the pre-check misses the duplicate and the unique name index rejects
    # the policy insert, which used to escape the IntegrityError guard as a 500.
    customer = (
        await client.post("/clients", json={"name": f"Policy {uuid4().hex}"})
    ).json()
    site = (
        await client.post("/sites", json={"client_id": customer["id"], "name": "HQ"})
    ).json()
    body = {**_policy("Équipe"), "scope": "site", "scope_id": site["id"]}
    first = await client.post("/monitoring/policies", json=body)
    assert first.status_code == 201, first.text
    second = await client.post("/monitoring/policies", json=body)
    assert second.status_code == 409, second.text
    assert second.json()["detail"]["code"] == "monitoring_policy_name_exists"
