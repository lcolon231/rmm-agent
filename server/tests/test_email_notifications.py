# SPDX-License-Identifier: AGPL-3.0-only
"""Alert email provider, escaping, retry, and idempotency tests (#45)."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_email_notifications.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core import email_notifications  # noqa: E402
from app.core import monitoring as monitoring_core  # noqa: E402
from app.core.config import Settings  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    Alert,
    AlertEmailAttempt,
    AlertEmailDelivery,
    AlertEvent,
    AlertEventType,
    AlertState,
    AuditEvent,
    CheckResultStatus,
    EmailAttemptStatus,
    EmailDeliveryStatus,
    Operator,
    OperatorRole,
)

NOW = datetime(2026, 8, 4, 15, 30, tzinfo=timezone.utc)


def _config(**overrides) -> Settings:
    values = {
        "email_alert_provider": "resend",
        "email_alert_resend_api_key": "re_test_secret_key",
        "email_alert_sender": "NodeLink <alerts@example.test>",
        "email_alert_recipients": "first@example.test, second@example.test",
        "email_alert_dashboard_base_url": "https://dashboard.example.test",
        "email_alert_backoff_base_seconds": 1,
        "email_alert_backoff_max_seconds": 4,
        "email_alert_max_attempts": 3,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


@pytest_asyncio.fixture
async def clean_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


def _delivery(*, max_attempts: int = 3) -> AlertEmailDelivery:
    return AlertEmailDelivery(
        id=str(uuid4()), alert_id=str(uuid4()), alert_event_id=str(uuid4()),
        generation=1, event_type=AlertEventType.opened,
        recipient="first@example.test", subject="NodeLink alert opened: cpu",
        text_body="Alert opened", html_body="<h2>Alert opened</h2>",
        status=EmailDeliveryStatus.pending, attempt_count=0,
        max_attempts=max_attempts, next_attempt_at=NOW - timedelta(seconds=1),
        created_at=NOW - timedelta(seconds=1), updated_at=NOW - timedelta(seconds=1),
    )


def test_configuration_rejects_invalid_recipient_without_echoing_it():
    config = _config(email_alert_recipients="valid@example.test, secret-token")
    problems = email_notifications.configuration_problems(config)
    assert problems == ["EMAIL_ALERT_RECIPIENTS contains an invalid address"]
    assert "secret-token" not in str(email_notifications.configuration_status(config))
    assert email_notifications.configured_recipients(config) == ()


def test_template_escapes_fields_and_excludes_comments_and_api_keys():
    config = _config()
    alert = Alert(
        id="alert-1", agent_id="agent<script>", policy_id="policy-1",
        policy_revision_id="revision-1", check_key="cpu<script>",
        state=AlertState.open, last_result_status=CheckResultStatus.critical,
        occurrence_count=1, total_occurrence_count=1, generation=1,
        version=2, last_value=99.5,
    )
    event = AlertEvent(
        id="event-1", alert_id=alert.id, generation=1,
        event_type=AlertEventType.opened, from_state=AlertState.resolved,
        to_state=AlertState.open, actor="operator@example.test",
        comment="Bearer must-not-appear", created_at=NOW,
    )
    subject, text_body, html_body = email_notifications._render_message(  # noqa: SLF001
        alert, event, config
    )
    assert "must-not-appear" not in subject + text_body + html_body
    assert config.email_alert_resend_api_key not in subject + text_body + html_body
    assert "<script>" not in html_body
    assert "cpu&lt;script&gt;" in html_body
    assert "https://dashboard.example.test/monitoring/alerts/alert-1" in html_body


@pytest.mark.asyncio
async def test_state_transition_enqueues_once_per_recipient(clean_db, monkeypatch):
    config = _config()
    for name in (
        "email_alert_provider", "email_alert_resend_api_key", "email_alert_sender",
        "email_alert_recipients", "email_alert_dashboard_base_url",
        "email_alert_max_attempts",
    ):
        monkeypatch.setattr(
            email_notifications.settings, name, getattr(config, name)
        )
    alert = Alert(
        id="alert-transition", agent_id="agent-1", policy_id="policy-1",
        policy_revision_id="revision-1", check_key="cpu",
        state=AlertState.open, last_result_status=CheckResultStatus.critical,
        occurrence_count=1, total_occurrence_count=1, generation=1, version=2,
    )
    async with AsyncSessionLocal() as db:
        db.add(alert)
        await monitoring_core._append_alert_event(  # noqa: SLF001
            db, alert, AlertEventType.opened,
            from_state=AlertState.resolved, to_state=AlertState.open,
            source_result_id="result-1", at=NOW,
        )
        alert.suppression_window_id = "maintenance-1"
        await monitoring_core._append_alert_event(  # noqa: SLF001
            db, alert, AlertEventType.reopened,
            from_state=AlertState.resolved, to_state=AlertState.open,
            source_result_id="result-2", at=NOW + timedelta(seconds=1),
        )
        await db.commit()
    async with AsyncSessionLocal() as db:
        deliveries = list((await db.execute(select(AlertEmailDelivery))).scalars().all())
        assert len(deliveries) == 4
        assert {item.recipient for item in deliveries} == {
            "first@example.test", "second@example.test",
        }
        assert len({item.alert_event_id for item in deliveries}) == 2
        assert [item.status for item in deliveries].count(EmailDeliveryStatus.pending) == 2
        assert [item.status for item in deliveries].count(EmailDeliveryStatus.suppressed) == 2


@pytest.mark.asyncio
async def test_retryable_failure_records_history_then_succeeds(clean_db):
    delivery = _delivery()
    async with AsyncSessionLocal() as db:
        db.add(delivery)
        await db.commit()

    class Provider:
        calls = 0

        async def send(self, _delivery):
            self.calls += 1
            if self.calls == 1:
                raise email_notifications.ProviderError("rate_limited", retryable=True)
            return "provider-message-1"

    provider = Provider()
    first = await email_notifications.process_due_deliveries(_config(), provider=provider)
    assert first.retrying == 1
    async with AsyncSessionLocal() as db:
        stored = await db.get(AlertEmailDelivery, delivery.id)
        assert stored.status == EmailDeliveryStatus.retrying
        assert stored.attempt_count == 1
        stored.next_attempt_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await db.commit()

    second = await email_notifications.process_due_deliveries(_config(), provider=provider)
    assert second.sent == 1
    async with AsyncSessionLocal() as db:
        stored = await db.get(AlertEmailDelivery, delivery.id)
        attempts = list(
            (
                await db.execute(
                    select(AlertEmailAttempt)
                    .where(AlertEmailAttempt.delivery_id == delivery.id)
                    .order_by(AlertEmailAttempt.attempt_number)
                )
            ).scalars().all()
        )
        assert stored.status == EmailDeliveryStatus.sent
        assert stored.provider_message_id == "provider-message-1"
        assert [item.status for item in attempts] == [
            EmailAttemptStatus.retrying, EmailAttemptStatus.sent,
        ]


@pytest.mark.asyncio
async def test_permanent_failure_does_not_retry(clean_db):
    delivery = _delivery()
    async with AsyncSessionLocal() as db:
        db.add(delivery)
        await db.commit()

    class Provider:
        async def send(self, _delivery):
            raise email_notifications.ProviderError("validation_error", retryable=False)

    result = await email_notifications.process_due_deliveries(_config(), provider=Provider())
    assert result.failed == 1
    async with AsyncSessionLocal() as db:
        stored = await db.get(AlertEmailDelivery, delivery.id)
        assert stored.status == EmailDeliveryStatus.failed
        assert stored.last_error_code == "validation_error"


@pytest.mark.asyncio
async def test_expired_claim_closes_old_attempt_before_retry(clean_db):
    delivery = _delivery()
    delivery.status = EmailDeliveryStatus.sending
    delivery.attempt_count = 1
    delivery.claimed_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    attempt = AlertEmailAttempt(
        id=str(uuid4()), delivery_id=delivery.id, attempt_number=1,
        status=EmailAttemptStatus.sending,
        created_at=delivery.claimed_at,
    )
    async with AsyncSessionLocal() as db:
        db.add_all([delivery, attempt])
        await db.commit()

    class Provider:
        async def send(self, _delivery):
            return "provider-message-after-lease"

    result = await email_notifications.process_due_deliveries(
        _config(email_alert_claim_timeout_seconds=30), provider=Provider()
    )
    assert result.sent == 1
    async with AsyncSessionLocal() as db:
        attempts = list(
            (
                await db.execute(
                    select(AlertEmailAttempt)
                    .where(AlertEmailAttempt.delivery_id == delivery.id)
                    .order_by(AlertEmailAttempt.attempt_number)
                )
            ).scalars().all()
        )
        assert [item.status for item in attempts] == [
            EmailAttemptStatus.retrying, EmailAttemptStatus.sent,
        ]
        assert attempts[0].error_code == "worker_lease_expired"
        assert attempts[0].completed_at is not None


@pytest.mark.asyncio
async def test_resend_adapter_uses_stable_idempotency_key(monkeypatch):
    requests: list[tuple[dict, dict]] = []

    class FakeClient:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def post(self, _url, *, headers, json):
            requests.append((headers, json))
            return httpx.Response(200, json={"id": "49a3999c-0ce1-4ea6-ab68-afcd6dc2e794"})

    monkeypatch.setattr(email_notifications.httpx, "AsyncClient", FakeClient)
    provider = email_notifications.ResendEmailProvider(_config())
    delivery = _delivery()
    assert await provider.send(delivery) == "49a3999c-0ce1-4ea6-ab68-afcd6dc2e794"
    assert await provider.send(delivery) == "49a3999c-0ce1-4ea6-ab68-afcd6dc2e794"
    assert requests[0][0]["Idempotency-Key"] == f"alert-email/{delivery.id}"
    assert requests[0][0]["Idempotency-Key"] == requests[1][0]["Idempotency-Key"]
    assert requests[0][1] == requests[1][1]
    assert "re_test_secret_key" not in str(requests[0][1])


@pytest.mark.asyncio
async def test_delivery_api_auth_masking_and_audited_retry(clean_db):
    alert = Alert(
        id="alert-api", agent_id="agent-api", policy_id="policy-api",
        policy_revision_id="revision-api", check_key="disk",
        state=AlertState.open, last_result_status=CheckResultStatus.critical,
        occurrence_count=1, total_occurrence_count=1, generation=1, version=1,
    )
    event = AlertEvent(
        id="event-api", alert_id=alert.id, generation=1,
        event_type=AlertEventType.opened, from_state=AlertState.resolved,
        to_state=AlertState.open, actor="system", created_at=NOW,
    )
    delivery = _delivery()
    delivery.id = "delivery-api"
    delivery.alert_id = alert.id
    delivery.alert_event_id = event.id
    delivery.status = EmailDeliveryStatus.failed
    delivery.attempt_count = delivery.max_attempts
    async with AsyncSessionLocal() as db:
        db.add_all([
            Operator(
                email="email-operator@example.test",
                password_hash=hash_password("operator-password"),
                role=OperatorRole.operator,
            ),
            Operator(
                email="email-viewer@example.test",
                password_hash=hash_password("viewer-password"),
                role=OperatorRole.readonly,
            ),
            alert, event, delivery,
        ])
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as client:
        assert (await client.get("/monitoring/email-alerts/status")).status_code == 401
        viewer_login = await client.post("/auth/login", json={
            "email": "email-viewer@example.test", "password": "viewer-password",
        })
        viewer_headers = {"Authorization": f"Bearer {viewer_login.json()['access_token']}"}
        history = await client.get(
            f"/monitoring/alerts/{alert.id}/email-deliveries", headers=viewer_headers,
        )
        assert history.status_code == 200
        assert history.json()["items"][0]["recipient"] == "f***@example.test"
        assert "first@example.test" not in history.text
        denied = await client.post(
            f"/monitoring/email-deliveries/{delivery.id}/retry",
            headers=viewer_headers, json={"request_id": "viewer-request-1234"},
        )
        assert denied.status_code == 403

        operator_login = await client.post("/auth/login", json={
            "email": "email-operator@example.test", "password": "operator-password",
        })
        operator_headers = {
            "Authorization": f"Bearer {operator_login.json()['access_token']}"
        }
        retried = await client.post(
            f"/monitoring/email-deliveries/{delivery.id}/retry",
            headers=operator_headers, json={"request_id": "operator-request-1234"},
        )
        assert retried.status_code == 200
        assert retried.json()["status"] == "retrying"

    async with AsyncSessionLocal() as db:
        audit_event = await db.scalar(
            select(AuditEvent).where(
                AuditEvent.action == "monitoring_alert_email.retried"
            )
        )
        assert audit_event is not None
        assert "recipient_sha256" in audit_event.detail
        assert "recipient" not in audit_event.detail
        assert "first@example.test" not in str(audit_event.detail)
