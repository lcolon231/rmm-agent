# SPDX-License-Identifier: AGPL-3.0-only
"""Signed webhook SSRF, rotation, retry, API, and redaction tests (#46)."""
from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

os.environ.setdefault(
    "DATABASE_URL", "sqlite+aiosqlite:///./test_webhook_notifications.db"
)
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core import webhook_notifications  # noqa: E402
from app.core.config import Settings  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    Alert,
    AlertEvent,
    AlertEventType,
    AlertState,
    AlertWebhookAttempt,
    AlertWebhookDelivery,
    AuditEvent,
    CheckResultStatus,
    Operator,
    OperatorRole,
    WebhookAttemptStatus,
    WebhookDeliveryStatus,
    WebhookEndpoint,
    WebhookSecretVersion,
)

NOW = datetime(2026, 8, 5, 0, 0, tzinfo=timezone.utc)
TEST_KEY = base64.urlsafe_b64encode(b"0123456789abcdef0123456789abcdef").decode()


def _config(**overrides) -> Settings:
    values = {
        "webhook_secret_encryption_key": TEST_KEY,
        "webhook_dns_timeout_seconds": 1,
        "webhook_request_timeout_seconds": 1,
        "webhook_backoff_base_seconds": 1,
        "webhook_backoff_max_seconds": 4,
        "webhook_max_attempts": 3,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


@pytest.mark.parametrize(
    ("setting", "value"),
    [
        ("webhook_poll_interval_seconds", 0),
        ("webhook_batch_size", 101),
        ("webhook_max_attempts", 21),
        ("webhook_claim_timeout_seconds", 29),
        ("webhook_request_timeout_seconds", 31),
        ("webhook_dns_timeout_seconds", 0),
        ("webhook_max_endpoints", 101),
    ],
)
def test_webhook_configuration_limits_fail_at_startup(setting, value):
    with pytest.raises(ValueError):
        _config(**{setting: value})


@pytest_asyncio.fixture
async def clean_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


def _alert_event() -> tuple[Alert, AlertEvent]:
    alert = Alert(
        id="alert-webhook",
        agent_id="agent-webhook",
        policy_id="policy-webhook",
        policy_revision_id="revision-webhook",
        check_key="cpu",
        state=AlertState.open,
        last_result_status=CheckResultStatus.critical,
        occurrence_count=1,
        total_occurrence_count=1,
        generation=1,
        version=2,
        last_value=99.5,
    )
    event = AlertEvent(
        id="event-webhook",
        alert_id=alert.id,
        generation=1,
        event_type=AlertEventType.opened,
        from_state=AlertState.resolved,
        to_state=AlertState.open,
        actor="operator-secret@example.test",
        comment="Bearer must-not-leak",
        created_at=NOW,
    )
    return alert, event


def _endpoint_secret(config: Settings) -> tuple[WebhookEndpoint, WebhookSecretVersion, str]:
    endpoint_id = "endpoint-webhook"
    secret_id = "secret-webhook-v1"
    plaintext = "whsec_test_delivery_secret"
    endpoint = WebhookEndpoint(
        id=endpoint_id,
        name="Operations",
        url="https://hooks.example.test/alerts?tenant=redacted",
        event_types=[AlertEventType.opened.value],
        enabled=True,
        current_secret_version=1,
        version=1,
        created_by="admin@example.test",
        updated_by="admin@example.test",
        created_at=NOW,
        updated_at=NOW,
    )
    secret = WebhookSecretVersion(
        id=secret_id,
        endpoint_id=endpoint_id,
        version=1,
        encrypted_secret=webhook_notifications.encrypt_secret(
            plaintext,
            endpoint_id=endpoint_id,
            secret_id=secret_id,
            version=1,
            config=config,
        ),
        created_by="admin@example.test",
        created_at=NOW,
    )
    return endpoint, secret, plaintext


def test_signature_vector_is_stable():
    payload = b'{"api_version":"2026-08-05","event_id":"event-1"}'
    assert webhook_notifications.signature_for(
        "whsec_test_vector_secret", payload, 1785945600
    ) == "v1=5470dd7d1a0b8aba0117fb301889fd0ecd6d1a47c124560a4cc5641ee675c169"


@pytest.mark.parametrize(
    ("url", "code", "state"),
    [
        ("http://example.com/hook", "unsupported_scheme", "unsupported"),
        ("https://user:pass@example.com/hook", "userinfo_not_allowed", "unsupported"),
        ("https://example.com:444/hook", "unsupported_port", "unsupported"),
        ("https://127.0.0.1/hook", "private_address", "invalid"),
        ("https://[::1]/hook", "private_address", "invalid"),
        ("https://localhost/hook", "invalid_hostname", "invalid"),
    ],
)
def test_destination_parser_rejects_unsafe_and_unsupported_urls(url, code, state):
    with pytest.raises(webhook_notifications.WebhookError) as caught:
        webhook_notifications.normalize_destination(url)
    assert (caught.value.code, caught.value.state) == (code, state)


@pytest.mark.asyncio
async def test_dns_rebinding_policy_rejects_any_private_answer(monkeypatch):
    class Loop:
        async def getaddrinfo(self, *_args, **_kwargs):
            return [
                (2, 1, 6, "", ("93.184.216.34", 443)),
                (2, 1, 6, "", ("10.0.0.8", 443)),
            ]

    monkeypatch.setattr(webhook_notifications.asyncio, "get_running_loop", Loop)
    with pytest.raises(webhook_notifications.WebhookError) as caught:
        await webhook_notifications.validate_destination(
            "https://hooks.example.test/alerts", _config()
        )
    assert caught.value.code == "private_address"
    assert caught.value.retryable is False


def test_secret_encryption_binds_endpoint_and_version():
    config = _config()
    secret = "whsec_rotation_safe_secret"
    encrypted = webhook_notifications.encrypt_secret(
        secret,
        endpoint_id="endpoint-1",
        secret_id="key-1",
        version=1,
        config=config,
    )
    assert secret not in encrypted
    assert webhook_notifications.decrypt_secret(
        encrypted,
        endpoint_id="endpoint-1",
        secret_id="key-1",
        version=1,
        config=config,
    ) == secret
    with pytest.raises(webhook_notifications.WebhookError) as caught:
        webhook_notifications.decrypt_secret(
            encrypted,
            endpoint_id="endpoint-1",
            secret_id="key-1",
            version=2,
            config=config,
        )
    assert caught.value.code == "secret_decryption_failed"


@pytest.mark.asyncio
async def test_enqueue_redacts_payload_and_rotation_preserves_inflight_key(clean_db):
    config = _config()
    alert, event = _alert_event()
    endpoint, secret_v1, plaintext_v1 = _endpoint_secret(config)
    async with AsyncSessionLocal() as db:
        db.add_all([alert, event, endpoint, secret_v1])
        await db.flush()
        assert await webhook_notifications.enqueue_alert_event(
            db, alert, event, config
        ) == 1
        await db.commit()

    # Rotate the endpoint after enqueue. The delivery must retain key v1.
    secret_v2_id = "secret-webhook-v2"
    async with AsyncSessionLocal() as db:
        stored_endpoint = await db.get(WebhookEndpoint, endpoint.id)
        stored_endpoint.current_secret_version = 2
        stored_endpoint.version = 2
        db.add(
            WebhookSecretVersion(
                id=secret_v2_id,
                endpoint_id=endpoint.id,
                version=2,
                encrypted_secret=webhook_notifications.encrypt_secret(
                    "whsec_new_secret",
                    endpoint_id=endpoint.id,
                    secret_id=secret_v2_id,
                    version=2,
                    config=config,
                ),
                created_by="admin@example.test",
                created_at=NOW + timedelta(seconds=1),
            )
        )
        await db.commit()

    captured: dict[str, object] = {}

    class Sender:
        async def send(self, delivery, secret):
            captured["secret"] = secret
            captured["payload"] = delivery.payload
            captured["delivery_id"] = delivery.id
            return 204

    result = await webhook_notifications.process_due_deliveries(
        config, sender=Sender()
    )
    assert result.delivered == 1
    assert captured["secret"] == plaintext_v1
    payload = json.loads(str(captured["payload"]))
    assert payload["delivery_id"] == captured["delivery_id"]
    assert "must-not-leak" not in str(payload)
    assert "operator-secret" not in str(payload)
    async with AsyncSessionLocal() as db:
        delivery = await db.scalar(select(AlertWebhookDelivery))
        attempt = await db.scalar(select(AlertWebhookAttempt))
        assert delivery.status == WebhookDeliveryStatus.delivered
        assert delivery.secret_version_id == secret_v1.id
        assert attempt.status == WebhookAttemptStatus.delivered
        assert attempt.http_status == 204


@pytest.mark.asyncio
async def test_retryable_failure_is_idempotent_and_records_history(clean_db):
    config = _config()
    alert, event = _alert_event()
    endpoint, secret, _plaintext = _endpoint_secret(config)
    async with AsyncSessionLocal() as db:
        db.add_all([alert, event, endpoint, secret])
        await db.flush()
        await webhook_notifications.enqueue_alert_event(db, alert, event, config)
        await db.commit()

    class Sender:
        calls = 0
        delivery_ids: list[str] = []

        async def send(self, delivery, _secret):
            self.calls += 1
            self.delivery_ids.append(delivery.id)
            if self.calls == 1:
                raise webhook_notifications.WebhookError(
                    "http_503", retryable=True, http_status=503
                )
            return 200

    sender = Sender()
    first = await webhook_notifications.process_due_deliveries(config, sender=sender)
    assert first.retrying == 1
    async with AsyncSessionLocal() as db:
        delivery = await db.scalar(select(AlertWebhookDelivery))
        delivery.next_attempt_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await db.commit()
    second = await webhook_notifications.process_due_deliveries(config, sender=sender)
    assert second.delivered == 1
    assert sender.delivery_ids[0] == sender.delivery_ids[1]
    async with AsyncSessionLocal() as db:
        attempts = list(
            (
                await db.execute(
                    select(AlertWebhookAttempt).order_by(
                        AlertWebhookAttempt.attempt_number
                    )
                )
            ).scalars().all()
        )
        assert [item.status for item in attempts] == [
            WebhookAttemptStatus.retrying,
            WebhookAttemptStatus.delivered,
        ]
        assert attempts[0].http_status == 503


@pytest.mark.asyncio
async def test_endpoint_api_authorization_rotation_masking_and_audit(
    clean_db, monkeypatch
):
    async def safe_destination(url, _config):
        destination = webhook_notifications.normalize_destination(url)
        return webhook_notifications.Destination(
            destination.url,
            destination.host,
            destination.port,
            destination.request_target,
            ("93.184.216.34",),
        )

    monkeypatch.setattr(
        webhook_notifications, "validate_destination", safe_destination
    )
    monkeypatch.setattr(
        webhook_notifications.settings, "webhook_secret_encryption_key", TEST_KEY
    )
    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                Operator(
                    email="webhook-admin@example.test",
                    password_hash=hash_password("admin-password"),
                    role=OperatorRole.admin,
                    is_platform_admin=True,
                ),
                Operator(
                    email="webhook-viewer@example.test",
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
        viewer_login = await client.post(
            "/auth/login",
            json={
                "email": "webhook-viewer@example.test",
                "password": "viewer-password",
            },
        )
        viewer_headers = {
            "Authorization": f"Bearer {viewer_login.json()['access_token']}"
        }
        denied = await client.post(
            "/monitoring/webhook-endpoints",
            headers=viewer_headers,
            json={
                "name": "Secret integration",
                "url": "https://hooks.example.test/secret-path?token=hidden",
                "event_types": ["opened"],
            },
        )
        assert denied.status_code == 403

        admin_login = await client.post(
            "/auth/login",
            json={
                "email": "webhook-admin@example.test",
                "password": "admin-password",
            },
        )
        admin_headers = {
            "Authorization": f"Bearer {admin_login.json()['access_token']}"
        }
        created = await client.post(
            "/monitoring/webhook-endpoints",
            headers=admin_headers,
            json={
                "name": "Secret integration",
                "url": "https://hooks.example.test/secret-path?token=hidden",
                "event_types": ["opened", "automatic_recovery"],
            },
        )
        assert created.status_code == 201, created.text
        created_body = created.json()
        first_secret = created_body["secret"]
        endpoint_id = created_body["id"]
        assert first_secret.startswith("whsec_")
        assert "secret-path" not in created_body["url"]
        assert "token" not in created.text

        listed = await client.get(
            "/monitoring/webhook-endpoints", headers=viewer_headers
        )
        assert listed.status_code == 200
        assert '"secret":' not in listed.text
        assert first_secret not in listed.text

        rotated = await client.post(
            f"/monitoring/webhook-endpoints/{endpoint_id}/rotate-secret",
            headers=admin_headers,
            json={
                "request_id": "rotate-request-1234",
                "expected_version": created_body["version"],
            },
        )
        assert rotated.status_code == 200, rotated.text
        assert rotated.json()["secret"] != first_secret
        assert rotated.json()["current_secret_version"] == 2

    async with AsyncSessionLocal() as db:
        secrets = list(
            (await db.execute(select(WebhookSecretVersion))).scalars().all()
        )
        assert len(secrets) == 2
        assert all(first_secret not in item.encrypted_secret for item in secrets)
        events = list(
            (
                await db.execute(
                    select(AuditEvent).where(
                        AuditEvent.action.in_(
                            [
                                "webhook_endpoint.created",
                                "webhook_endpoint.secret_rotated",
                            ]
                        )
                    )
                )
            ).scalars().all()
        )
        assert len(events) == 2
        serialized = str([item.detail for item in events])
        assert first_secret not in serialized
        assert "secret-path" not in serialized
        assert "url_sha256" in serialized
