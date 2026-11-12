# SPDX-License-Identifier: AGPL-3.0-only
"""The webhook event catalog is the single, published truth (issue #72).

The catalog, the subscription validator, the delivery queue, the JSON Schema,
the signed vectors, and docs/WEBHOOK-EVENTS.md must agree. Each test pins one
of those edges so an event cannot ship undocumented or unsigned.
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_webhook_catalog.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import hashlib  # noqa: E402
import hmac  # noqa: E402
import json  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
from pathlib import Path  # noqa: E402

from jsonschema import Draft202012Validator  # noqa: E402

from app.core import public_contracts, webhook_catalog, webhook_notifications  # noqa: E402
from app.models.models import (  # noqa: E402
    Alert,
    AlertEvent,
    AlertEventType,
    AlertState,
    CheckResultStatus,
)
from app.schemas import monitoring as monitoring_schemas  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "contracts" / "webhook-event-v1.schema.json").read_text(encoding="utf-8"))
VECTORS = json.loads(
    (ROOT / "contracts" / "test-vectors" / "webhook-event-v1.json").read_text(encoding="utf-8")
)
DOC = (ROOT / "docs" / "WEBHOOK-EVENTS.md").read_text(encoding="utf-8")


def test_registries_derive_from_the_catalog():
    sources = {event.source for event in webhook_catalog.CATALOG}
    assert monitoring_schemas.WEBHOOK_EVENT_TYPES == sources
    assert webhook_notifications.SUPPORTED_EVENT_TYPES == {s.value for s in sources}
    # Non-deliverable lifecycle events stay out on purpose: assignment and
    # comments are collaboration noise, import is a migration artifact.
    assert set(AlertEventType) - sources == {
        AlertEventType.state_imported,
        AlertEventType.assigned,
        AlertEventType.commented,
    }


def test_schema_enumerates_exactly_the_catalog():
    assert SCHEMA["properties"]["event_type"]["enum"] == [
        event.event_type for event in webhook_catalog.CATALOG
    ]
    assert SCHEMA["properties"]["api_version"]["const"] == webhook_catalog.WEBHOOK_API_VERSION


def test_every_example_and_live_payload_validates():
    validator = Draft202012Validator(SCHEMA)
    for event in webhook_catalog.CATALOG:
        assert not list(validator.iter_errors(webhook_catalog.example_body(event)))

    now = datetime(2026, 8, 5, 16, 0, tzinfo=timezone.utc)
    alert = Alert(
        id="a1", agent_id="e1", policy_id="p1", policy_revision_id="r1",
        check_key="cpu", state=AlertState.open,
        last_result_status=CheckResultStatus.critical, last_value=97.0,
        occurrence_count=1, total_occurrence_count=1, generation=1, version=1,
    )
    for event in webhook_catalog.CATALOG:
        alert_event = AlertEvent(
            id="ev1", alert_id="a1", generation=1, event_type=event.source,
            from_state=AlertState(event.from_state) if event.from_state else None,
            to_state=AlertState(event.to_state), actor="system", created_at=now,
        )
        body = json.loads(
            webhook_notifications.build_payload(alert, alert_event, delivery_id="d1")
        )
        assert not list(validator.iter_errors(body)), event.event_type
        assert body["event_type"] == event.event_type


def test_signed_vectors_are_current_and_verify_independently():
    assert VECTORS == json.loads(public_contracts.render(public_contracts.build_webhook_vectors()))
    assert [v["event_type"] for v in VECTORS["vectors"]] == [
        e.event_type for e in webhook_catalog.CATALOG
    ]
    secret = VECTORS["secret"].encode("ascii")
    for vector in VECTORS["vectors"]:
        headers = vector["headers"]
        # Re-derive with nothing but the stdlib, exactly as a receiver would.
        signed = f"v1.{headers['X-NodeLink-Timestamp']}.".encode("ascii") + vector["body"].encode("utf-8")
        expected = "v1=" + hmac.new(secret, signed, hashlib.sha256).hexdigest()
        assert headers["X-NodeLink-Signature"] == expected
        body = json.loads(vector["body"])
        assert headers["X-NodeLink-Event-Id"] == body["event_id"]
        assert headers["X-NodeLink-Delivery-Id"] == body["delivery_id"]
        assert headers["X-NodeLink-Webhook-Version"] == body["api_version"]
        assert headers["Idempotency-Key"] == f"nodelink-webhook/{body['delivery_id']}"
        # The body is canonical: re-serialising cannot change a signed byte.
        assert webhook_catalog.canonical_json(body) == vector["body"]


def test_legacy_signature_vector_is_unchanged():
    """The #46 vector still holds: the catalog changed no signed bytes."""
    payload = b'{"api_version":"2026-08-05","event_id":"event-1"}'
    assert webhook_notifications.signature_for("whsec_test_vector_secret", payload, 1785945600) == (
        "v1=5470dd7d1a0b8aba0117fb301889fd0ecd6d1a47c124560a4cc5641ee675c169"
    )


def test_every_catalog_event_and_header_is_documented():
    for event in webhook_catalog.CATALOG:
        assert f"`{event.event_type}`" in DOC, event.event_type
        assert f"`{event.source.value}`" in DOC, event.source.value
    for header in VECTORS["vectors"][0]["headers"]:
        assert f"`{header}`" in DOC, header
    for field in SCHEMA["properties"]["data"]["properties"]["alert"]["required"]:
        assert f"`{field}`" in DOC, field
    assert webhook_catalog.WEBHOOK_API_VERSION in DOC
