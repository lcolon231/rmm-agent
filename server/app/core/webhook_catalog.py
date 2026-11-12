# SPDX-License-Identifier: AGPL-3.0-only
"""The versioned webhook event catalog (issue #72) -- the one registry.

Every event NodeLink may sign and deliver to a webhook endpoint is listed here
with its wire name, meaning, schema version, and a canonical example. The
subscription validator (``app.schemas.monitoring``), the delivery queue
(``app.core.webhook_notifications``), the published JSON Schema
(``contracts/webhook-event-v1.schema.json``), the signed test vectors
(``contracts/test-vectors/webhook-event-v1.json``) and
``docs/WEBHOOK-EVENTS.md`` are all checked against this module, so an event
cannot be emitted without being documented, or documented without existing.

Versioning: a payload carries ``api_version`` (a date). Within one version,
fields are only ever *added*; receivers must ignore unknown fields. A removal,
rename, or meaning change ships as a new ``api_version`` date.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from app.models.models import AlertEventType

#: The payload contract version every delivery is signed under today.
WEBHOOK_API_VERSION = "2026-08-05"

#: Versions this server can emit. Newest last.
SUPPORTED_WEBHOOK_API_VERSIONS: tuple[str, ...] = (WEBHOOK_API_VERSION,)

#: Wire prefix for alert lifecycle events.
ALERT_EVENT_PREFIX = "monitoring.alert."

#: Fixed inputs for the published, reproducible signing vectors. Test-only:
#: never a real endpoint secret.
VECTOR_SECRET = "whsec_test_vector_secret"
VECTOR_TIMESTAMP = 1785945600  # 2026-08-05T16:00:00Z
VECTOR_SECRET_VERSION_ID = "4b0e1c55-2f8e-4d0a-9a61-7c3b5d2e8f10"


@dataclass(frozen=True)
class WebhookEvent:
    source: AlertEventType
    description: str
    from_state: str | None
    to_state: str
    result_status: str
    schema_version: int = 1
    since: str = WEBHOOK_API_VERSION

    @property
    def event_type(self) -> str:
        return f"{ALERT_EVENT_PREFIX}{self.source.value}"


CATALOG: tuple[WebhookEvent, ...] = (
    WebhookEvent(
        AlertEventType.opened,
        "A monitoring check crossed its threshold and a new alert opened.",
        None, "open", "critical",
    ),
    WebhookEvent(
        AlertEventType.reopened,
        "A previously resolved alert for the same check fired again.",
        "resolved", "open", "warning",
    ),
    WebhookEvent(
        AlertEventType.acknowledged,
        "A technician acknowledged an open alert.",
        "open", "acknowledged", "critical",
    ),
    WebhookEvent(
        AlertEventType.manual_resolution,
        "A technician resolved an alert by hand.",
        "acknowledged", "resolved", "critical",
    ),
    WebhookEvent(
        AlertEventType.automatic_recovery,
        "The check recovered and the alert resolved itself.",
        "open", "resolved", "ok",
    ),
    WebhookEvent(
        AlertEventType.policy_revised,
        "The monitoring policy changed and the alert was closed under the old revision.",
        "open", "resolved", "warning",
    ),
    WebhookEvent(
        AlertEventType.policy_deleted,
        "The monitoring policy was deleted and its alert was closed.",
        "open", "resolved", "warning",
    ),
    WebhookEvent(
        AlertEventType.policy_superseded,
        "A higher-precedence policy took over the check and the alert was closed.",
        "open", "resolved", "warning",
    ),
)

#: Subscription values (bare ``AlertEventType``) that may be delivered.
WEBHOOK_EVENT_SOURCES: frozenset[AlertEventType] = frozenset(
    event.source for event in CATALOG
)

_BY_SOURCE = {event.source: event for event in CATALOG}


def wire_event_type(source: AlertEventType) -> str:
    return f"{ALERT_EVENT_PREFIX}{source.value}"


def lookup(source: AlertEventType) -> WebhookEvent | None:
    return _BY_SOURCE.get(source)


def example_body(event: WebhookEvent) -> dict:
    """A deterministic example payload, identical in shape to ``build_payload``."""
    index = CATALOG.index(event) + 1
    return {
        "api_version": WEBHOOK_API_VERSION,
        "delivery_id": f"00000000-0000-4000-8000-{index:012d}",
        "event_id": f"00000000-0000-4000-9000-{index:012d}",
        "event_type": event.event_type,
        "occurred_at": "2026-08-05T16:00:00Z",
        "data": {
            "alert": {
                "id": "6f1c2b8e-3a4d-4e5f-8a9b-0c1d2e3f4a5b",
                "endpoint_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
                "policy_id": "1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e",
                "policy_revision_id": "2c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e6f",
                "check_key": "disk_free_percent",
                "generation": 1,
                "from_state": event.from_state,
                "to_state": event.to_state,
                "result_status": event.result_status,
                "last_value": 4.5 if event.result_status != "ok" else 41.0,
            }
        },
    }


def canonical_json(body: dict) -> str:
    """The exact byte form NodeLink signs: sorted keys, no spaces, UTF-8."""
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
