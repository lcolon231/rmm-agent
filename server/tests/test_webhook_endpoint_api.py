# SPDX-License-Identifier: AGPL-3.0-only
"""HTTP coverage for webhook endpoint management and delivery retry (#284).

`test_webhook_notifications.py` covers the delivery engine and the create /
rotate happy path. This module drives every remaining route over HTTP and
walks each refusal branch: status, update, validate, delete, the per-alert
delivery list, and manual retry.
"""
from __future__ import annotations

import base64
import os
from datetime import datetime, timezone

os.environ.setdefault(
    "DATABASE_URL", "sqlite+aiosqlite:///./test_webhook_endpoint_api.db"
)
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402

from app.core import webhook_notifications  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    Alert,
    AlertEventType,
    AlertState,
    AlertWebhookAttempt,
    AlertWebhookDelivery,
    CheckResultStatus,
    Operator,
    OperatorRole,
    WebhookAttemptStatus,
    WebhookDeliveryStatus,
    WebhookSecretVersion,
)

NOW = datetime(2026, 8, 5, 0, 0, tzinfo=timezone.utc)
TEST_KEY = base64.urlsafe_b64encode(b"0123456789abcdef0123456789abcdef").decode()
ADMIN = ("hook-admin@example.test", "admin-password")
VIEWER = ("hook-viewer@example.test", "viewer-password")
URL = "https://hooks.example.test/path?token=hidden"


async def _safe_destination(url, _config):
    parsed = webhook_notifications.normalize_destination(url)
    return webhook_notifications.Destination(
        parsed.url, parsed.host, parsed.port, parsed.request_target, ("93.184.216.34",)
    )


@pytest_asyncio.fixture
async def client(monkeypatch):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    monkeypatch.setattr(webhook_notifications, "validate_destination", _safe_destination)
    monkeypatch.setattr(
        webhook_notifications.settings, "webhook_secret_encryption_key", TEST_KEY
    )
    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                Operator(
                    email=ADMIN[0],
                    password_hash=hash_password(ADMIN[1]),
                    role=OperatorRole.admin,
                    is_platform_admin=True,
                ),
                Operator(
                    email=VIEWER[0],
                    password_hash=hash_password(VIEWER[1]),
                    role=OperatorRole.readonly,
                ),
            ]
        )
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        for name, (email, password) in (("admin", ADMIN), ("viewer", VIEWER)):
            login = await c.post("/auth/login", json={"email": email, "password": password})
            setattr(c, name, {"Authorization": f"Bearer {login.json()['access_token']}"})
        yield c
    await engine.dispose()


async def _create(c, name="Ops") -> dict:
    created = await c.post(
        "/monitoring/webhook-endpoints",
        headers=c.admin,
        json={"name": name, "url": URL, "event_types": ["opened"]},
    )
    assert created.status_code == 201, created.text
    return created.json()


def _rid(n: int) -> str:
    return f"req-{n:012d}-abcd"


async def test_status_reports_counts_without_secrets(client):
    await _create(client)
    status = await client.get("/monitoring/webhooks/status", headers=client.viewer)
    assert status.status_code == 200, status.text
    body = status.json()
    assert body["encryption_key_configured"] is True
    assert body["endpoint_count"] == 1
    assert body["enabled_endpoint_count"] == 1
    assert "secret" not in status.text


async def test_create_refusals(client, monkeypatch):
    # Destination rejected by the SSRF guard -> 422 with the guard's code.
    async def reject(_url, _config):
        raise webhook_notifications.WebhookError("destination_private", state="rejected", retryable=False)

    monkeypatch.setattr(webhook_notifications, "validate_destination", reject)
    bad = await client.post(
        "/monitoring/webhook-endpoints",
        headers=client.admin,
        json={"name": "Bad", "url": URL},
    )
    assert bad.status_code == 422
    assert bad.json()["detail"]["code"] == "destination_private"
    monkeypatch.setattr(webhook_notifications, "validate_destination", _safe_destination)

    await _create(client, "Ops")
    duplicate = await client.post(
        "/monitoring/webhook-endpoints",
        headers=client.admin,
        json={"name": "Ops", "url": URL},
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"]["code"] == "webhook_endpoint_name_exists"

    monkeypatch.setattr(webhook_notifications.settings, "webhook_max_endpoints", 1)
    limited = await client.post(
        "/monitoring/webhook-endpoints",
        headers=client.admin,
        json={"name": "Second", "url": URL},
    )
    assert limited.status_code == 409
    assert limited.json()["detail"]["code"] == "webhook_endpoint_limit_reached"
    monkeypatch.setattr(webhook_notifications.settings, "webhook_max_endpoints", 25)

    monkeypatch.setattr(
        webhook_notifications.settings, "webhook_secret_encryption_key", None
    )
    no_key = await client.post(
        "/monitoring/webhook-endpoints",
        headers=client.admin,
        json={"name": "Third", "url": URL},
    )
    assert no_key.status_code == 503
    assert "code" in no_key.json()["detail"]


async def test_update_happy_path_and_refusals(client, monkeypatch):
    endpoint = await _create(client, "Ops")
    await _create(client, "Other")
    path = f"/monitoring/webhook-endpoints/{endpoint['id']}"

    missing = await client.put(
        "/monitoring/webhook-endpoints/nope",
        headers=client.admin,
        json={"request_id": _rid(1), "expected_version": 1, "enabled": True},
    )
    assert missing.status_code == 404

    stale = await client.put(
        path, headers=client.admin, json={"request_id": _rid(2), "expected_version": 9, "enabled": True}
    )
    assert stale.status_code == 409
    assert stale.json()["detail"] == {
        "code": "webhook_endpoint_version_conflict",
        "current_version": 1,
    }

    clash = await client.put(
        path,
        headers=client.admin,
        json={"request_id": _rid(3), "expected_version": 1, "name": "Other"},
    )
    assert clash.status_code == 409
    assert clash.json()["detail"]["code"] == "webhook_endpoint_name_exists"

    async def reject(_url, _config):
        raise webhook_notifications.WebhookError("destination_private", state="rejected", retryable=False)

    monkeypatch.setattr(webhook_notifications, "validate_destination", reject)
    bad_url = await client.put(
        path,
        headers=client.admin,
        json={"request_id": _rid(4), "expected_version": 1, "url": URL},
    )
    assert bad_url.status_code == 422
    monkeypatch.setattr(webhook_notifications, "validate_destination", _safe_destination)

    denied = await client.put(
        path, headers=client.viewer, json={"request_id": _rid(5), "expected_version": 1, "enabled": True}
    )
    assert denied.status_code == 403

    updated = await client.put(
        path,
        headers=client.admin,
        json={
            "request_id": _rid(6),
            "expected_version": 1,
            "name": "Renamed",
            "url": URL,
            "event_types": ["opened", "automatic_recovery"],
            "enabled": False,
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["name"] == "Renamed"
    assert updated.json()["enabled"] is False
    assert updated.json()["version"] == 2


async def test_validate_reports_state_and_refuses_unknown(client, monkeypatch):
    endpoint = await _create(client)
    path = f"/monitoring/webhook-endpoints/{endpoint['id']}/validate"

    missing = await client.post(
        "/monitoring/webhook-endpoints/nope/validate", headers=client.admin
    )
    assert missing.status_code == 404
    readonly = await client.post(path, headers=client.viewer)
    assert readonly.status_code == 403

    valid = await client.post(path, headers=client.admin)
    assert valid.status_code == 200, valid.text
    assert valid.json()["state"] == "valid"
    assert valid.json()["resolved_address_count"] == 1

    async def reject(_url, _config):
        raise webhook_notifications.WebhookError("dns_private_answer", state="rejected", retryable=False)

    monkeypatch.setattr(webhook_notifications, "validate_destination", reject)
    invalid = await client.post(path, headers=client.admin)
    assert invalid.status_code == 200
    assert invalid.json()["code"] == "dns_private_answer"
    assert invalid.json()["resolved_address_count"] == 0


async def test_rotate_refusals(client, monkeypatch):
    endpoint = await _create(client)
    path = f"/monitoring/webhook-endpoints/{endpoint['id']}/rotate-secret"

    missing = await client.post(
        "/monitoring/webhook-endpoints/nope/rotate-secret",
        headers=client.admin,
        json={"request_id": _rid(1), "expected_version": 1},
    )
    assert missing.status_code == 404
    stale = await client.post(
        path, headers=client.admin, json={"request_id": _rid(2), "expected_version": 7}
    )
    assert stale.status_code == 409
    assert stale.json()["detail"]["code"] == "webhook_endpoint_version_conflict"

    monkeypatch.setattr(
        webhook_notifications.settings, "webhook_secret_encryption_key", None
    )
    no_key = await client.post(
        path, headers=client.admin, json={"request_id": _rid(3), "expected_version": 1}
    )
    assert no_key.status_code == 503
    monkeypatch.setattr(
        webhook_notifications.settings, "webhook_secret_encryption_key", TEST_KEY
    )

    # The current secret row vanished: rotation must fail closed rather than
    # minting a version that cannot be traced back to its predecessor.
    async with AsyncSessionLocal() as db:
        secret = await db.get(WebhookSecretVersion, endpoint["current_secret_key_id"])
        await db.delete(secret)
        await db.commit()
    orphan = await client.post(
        path, headers=client.admin, json={"request_id": _rid(4), "expected_version": 1}
    )
    assert orphan.status_code == 409
    assert orphan.json()["detail"]["code"] == "webhook_secret_version_unavailable"


async def test_delete_soft_deletes_and_refuses(client):
    endpoint = await _create(client)
    path = f"/monitoring/webhook-endpoints/{endpoint['id']}"

    missing = await client.delete(
        "/monitoring/webhook-endpoints/nope",
        headers=client.admin,
        params={"request_id": _rid(1), "expected_version": 1},
    )
    assert missing.status_code == 404
    stale = await client.delete(
        path, headers=client.admin, params={"request_id": _rid(2), "expected_version": 4}
    )
    assert stale.status_code == 409
    denied = await client.delete(
        path, headers=client.viewer, params={"request_id": _rid(3), "expected_version": 1}
    )
    assert denied.status_code == 403

    deleted = await client.delete(
        path, headers=client.admin, params={"request_id": _rid(4), "expected_version": 1}
    )
    assert deleted.status_code == 204
    listed = await client.get("/monitoring/webhook-endpoints", headers=client.viewer)
    assert listed.json() == []
    again = await client.delete(
        path, headers=client.admin, params={"request_id": _rid(5), "expected_version": 2}
    )
    assert again.status_code == 404
    validate = await client.post(f"{path}/validate", headers=client.admin)
    assert validate.status_code == 404


async def _seed_delivery(endpoint: dict, *, status, attempt_count=1) -> str:
    async with AsyncSessionLocal() as db:
        db.add(
            Alert(
                id="alert-1",
                agent_id="agent-1",
                policy_id="policy-1",
                policy_revision_id="revision-1",
                check_key="cpu",
                state=AlertState.open,
                last_result_status=CheckResultStatus.critical,
                occurrence_count=1,
                total_occurrence_count=1,
                generation=1,
                version=1,
            )
        )
        db.add(
            AlertWebhookDelivery(
                id="delivery-1",
                endpoint_id=endpoint["id"],
                secret_version_id=endpoint["current_secret_key_id"],
                alert_id="alert-1",
                alert_event_id="event-1",
                generation=1,
                event_type=AlertEventType.opened,
                destination_url=URL,
                payload="{}",
                signature_timestamp=int(NOW.timestamp()),
                status=status,
                attempt_count=attempt_count,
                max_attempts=3,
                next_attempt_at=NOW,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        db.add(
            AlertWebhookAttempt(
                id="attempt-1",
                delivery_id="delivery-1",
                attempt_number=1,
                status=WebhookAttemptStatus.failed,
                http_status=500,
                created_at=NOW,
            )
        )
        await db.commit()
    return "delivery-1"


async def test_delivery_list_masks_destination_and_404s_unknown_alert(client):
    endpoint = await _create(client)
    await _seed_delivery(endpoint, status=WebhookDeliveryStatus.failed)

    unknown = await client.get(
        "/monitoring/alerts/nope/webhook-deliveries", headers=client.viewer
    )
    assert unknown.status_code == 404
    listed = await client.get(
        "/monitoring/alerts/alert-1/webhook-deliveries", headers=client.viewer
    )
    assert listed.status_code == 200, listed.text
    [item] = listed.json()["items"]
    assert item["endpoint_name"] == "Ops"
    assert len(item["attempts"]) == 1
    assert "token=hidden" not in listed.text


async def test_retry_is_idempotent_and_refuses_bad_states(client):
    endpoint = await _create(client)
    delivery_id = await _seed_delivery(endpoint, status=WebhookDeliveryStatus.failed)
    path = f"/monitoring/webhook-deliveries/{delivery_id}/retry"

    missing = await client.post(
        "/monitoring/webhook-deliveries/nope/retry",
        headers=client.admin,
        json={"request_id": _rid(1)},
    )
    assert missing.status_code == 404
    readonly = await client.post(path, headers=client.viewer, json={"request_id": _rid(1)})
    assert readonly.status_code == 403

    retried = await client.post(path, headers=client.admin, json={"request_id": _rid(2)})
    assert retried.status_code == 200, retried.text
    assert retried.json()["status"] == "retrying"
    # Same request id replays the stored result instead of re-queueing.
    replay = await client.post(path, headers=client.admin, json={"request_id": _rid(2)})
    assert replay.status_code == 200
    assert replay.json()["status"] == "retrying"
    # A fresh request against a delivery that is no longer failed is refused.
    wrong_state = await client.post(path, headers=client.admin, json={"request_id": _rid(3)})
    assert wrong_state.status_code == 409
    assert wrong_state.json()["detail"]["code"] == "webhook_delivery_retry_invalid_state"

    async with AsyncSessionLocal() as db:
        delivery = await db.get(AlertWebhookDelivery, delivery_id)
        delivery.status = WebhookDeliveryStatus.failed
        delivery.attempt_count = 20
        await db.commit()
    exhausted = await client.post(path, headers=client.admin, json={"request_id": _rid(4)})
    assert exhausted.status_code == 409
    assert exhausted.json()["detail"]["code"] == "webhook_delivery_retry_limit_reached"
