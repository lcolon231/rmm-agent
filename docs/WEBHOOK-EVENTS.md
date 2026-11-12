# Webhook event catalog

Status: implemented (issue #72), on top of the signed delivery system from
issue #46 ([`SIGNED-WEBHOOKS.md`](SIGNED-WEBHOOKS.md)). This page is the
versioned contract for what a webhook receiver gets. The single source of
truth in code is `server/app/core/webhook_catalog.py`. The published artifacts
below are generated from it and checked by `server/tests/test_webhook_catalog.py`
and `server/tests/test_contract_schemas.py`, so an event cannot be delivered
without appearing here.

| Artifact | Path |
| --- | --- |
| JSON Schema (draft 2020-12) | [`contracts/webhook-event-v1.schema.json`](../contracts/webhook-event-v1.schema.json) |
| Signed test vectors, one per event | [`contracts/test-vectors/webhook-event-v1.json`](../contracts/test-vectors/webhook-event-v1.json) |
| Regenerate the vectors | `cd server && python scripts/export_public_contracts.py` |

## Versioning

Every payload carries `api_version`, a date. The current and only version is
**`2026-08-05`**. `GET /api/v1/api-version` lists every version this server can
emit (`webhook_api_versions`).

- **Inside one `api_version`, fields are only added.** No field is removed,
  renamed, retyped, or given a new meaning. Receivers **must ignore unknown
  fields**. The schema permits additional properties for this reason.
- **Breaking changes ship as a new `api_version` date.** A destination keeps
  receiving the old version for at least 180 days after the new version is
  announced in release notes and in `webhook_api_versions`, matching the API
  deprecation window in [`PUBLIC-API.md`](PUBLIC-API.md#deprecation-policy).
- **New event types are additive.** A destination receives only the event
  types it subscribed to, so a new event never reaches an existing receiver
  until an administrator adds it to that destination.
- Each event has its own `schema_version` (currently `1` for all) in the
  catalog and the vectors. It increments only together with a new
  `api_version`.

Receivers should reject an `api_version` they do not know, rather than guess.

## Events

The subscription value is what you list in a destination's `event_types`. The
wire `event_type` is what the payload carries.

| Wire `event_type` | Subscription value | Meaning | `from_state` → `to_state` |
| --- | --- | --- | --- |
| `monitoring.alert.opened` | `opened` | A monitoring check crossed its threshold and a new alert opened. | `null` → `open` |
| `monitoring.alert.reopened` | `reopened` | A previously resolved alert for the same check fired again. | `resolved` → `open` |
| `monitoring.alert.acknowledged` | `acknowledged` | A technician acknowledged an open alert. | `open` → `acknowledged` |
| `monitoring.alert.manual_resolution` | `manual_resolution` | A technician resolved an alert by hand. | `open`/`acknowledged` → `resolved` |
| `monitoring.alert.automatic_recovery` | `automatic_recovery` | The check recovered and the alert resolved itself. | `open`/`acknowledged` → `resolved` |
| `monitoring.alert.policy_revised` | `policy_revised` | The policy changed and the alert closed under the old revision. | → `resolved` |
| `monitoring.alert.policy_deleted` | `policy_deleted` | The policy was deleted and its alert closed. | → `resolved` |
| `monitoring.alert.policy_superseded` | `policy_superseded` | A higher-precedence policy took over the check and the alert closed. | → `resolved` |

These alert lifecycle events are deliberately **not** delivered: `assigned`
and `commented` (technician collaboration noise) and `state_imported` (a
migration artifact).

## Payload

All events share one envelope:

| Field | Type | Meaning |
| --- | --- | --- |
| `api_version` | string | Payload contract version, `2026-08-05`. |
| `delivery_id` | string | Stable across retries of this delivery. Use it as your dedupe key. |
| `event_id` | string | The alert event. One event fans out to one delivery per destination. |
| `event_type` | string | One of the wire names above. |
| `occurred_at` | string | UTC RFC 3339 time of the alert event, `Z` suffix. |
| `data.alert` | object | The alert at the moment of the event (below). |

`data.alert` fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | Alert identifier. Matches `GET /api/v1/monitoring/alerts/{alert_id}`. |
| `endpoint_id` | string | Managed endpoint (agent) the alert is on. Matches `GET /api/v1/endpoints/{endpoint_id}`. |
| `policy_id` | string | Monitoring policy that raised it. |
| `policy_revision_id` | string | Exact policy revision in force. |
| `check_key` | string | The check within that policy. |
| `generation` | integer | Incremented each time the alert reopens. |
| `from_state` | string or null | Previous state, or `null` when the alert opens. |
| `to_state` | string | `open`, `acknowledged`, or `resolved`. |
| `result_status` | string | Latest check result: `ok`, `warning`, `critical`, or `unknown`. |
| `last_value` | number or null | Latest measured value, when the check has one. |

Payloads never contain hostnames, file paths, script output, recipient
addresses, or secrets. Look up details through the public API with an API
token scoped to the right tenant.

Example (`monitoring.alert.opened`, from the signed vectors):

```json
{
  "api_version": "2026-08-05",
  "data": {
    "alert": {
      "check_key": "disk_free_percent",
      "endpoint_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "from_state": null,
      "generation": 1,
      "id": "6f1c2b8e-3a4d-4e5f-8a9b-0c1d2e3f4a5b",
      "last_value": 4.5,
      "policy_id": "1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e",
      "policy_revision_id": "2c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e6f",
      "result_status": "critical",
      "to_state": "open"
    }
  },
  "delivery_id": "00000000-0000-4000-8000-000000000001",
  "event_id": "00000000-0000-4000-9000-000000000001",
  "event_type": "monitoring.alert.opened",
  "occurred_at": "2026-08-05T16:00:00Z"
}
```

On the wire the body is canonical JSON: sorted keys, no insignificant
whitespace, UTF-8. **Verify the signature over the raw bytes you received,
never over a re-serialized object.**

## Headers

| Header | Meaning |
| --- | --- |
| `X-NodeLink-Webhook-Version` | Same as `api_version`. |
| `X-NodeLink-Event-Id` | Same as `event_id`. |
| `X-NodeLink-Delivery-Id` | Same as `delivery_id`. |
| `Idempotency-Key` | `nodelink-webhook/<delivery_id>`. |
| `X-NodeLink-Timestamp` | Unix seconds, fixed when the delivery was queued. Identical on every retry. |
| `X-NodeLink-Signature` | `v1=` + lowercase hex HMAC-SHA256. |
| `X-NodeLink-Key-Id` | The secret version that signed it. Lets you hold two secrets during rotation. |

## Verifying a delivery

The signed string is `v1.` + `X-NodeLink-Timestamp` + `.` + raw body. The key
is the destination secret (`whsec_...`) as ASCII bytes.

Python:

```python
import hashlib, hmac

def verify(secret: str, headers: dict, raw_body: bytes) -> bool:
    signed = f"v1.{headers['X-NodeLink-Timestamp']}.".encode() + raw_body
    expected = "v1=" + hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, headers["X-NodeLink-Signature"])
```

Node.js:

```js
const crypto = require("node:crypto");

function verify(secret, headers, rawBody /* Buffer */) {
  const signed = Buffer.concat([
    Buffer.from(`v1.${headers["x-nodelink-timestamp"]}.`), rawBody,
  ]);
  const expected = "v1=" + crypto.createHmac("sha256", secret).update(signed).digest("hex");
  const got = Buffer.from(headers["x-nodelink-signature"] ?? "");
  return got.length === expected.length && crypto.timingSafeEqual(got, Buffer.from(expected));
}
```

Check your implementation against
`contracts/test-vectors/webhook-event-v1.json`. Every vector there must verify
with secret `whsec_test_vector_secret` and timestamp `1785945600`.

**Replay window.** The timestamp is fixed when the delivery is queued. Retries
can therefore arrive hours later, up to the configured backoff ceiling times
the attempt count, with the original timestamp. Use the replay window to
reject *old, never-seen* deliveries, not retries. Dedupe on `delivery_id`
(record it before applying side effects, and treat a repeat as success). A
window of 24 hours covers the default retry schedule.

## Delivery semantics

Delivery is at-least-once, per destination, with no ordering guarantee
between events. Order by `occurred_at`, then `generation`. Retries, rotation,
manual retry, and recovery are described in
[`SIGNED-WEBHOOKS.md`](SIGNED-WEBHOOKS.md).

Webhook destinations are deployment-level configuration managed by
administrators. Delivery history and manual retry are tenant-scoped: an
operator can see or retry a delivery only for an alert whose endpoint is in a
client they belong to. A foreign delivery returns `404`, the same as a missing
one (issue #72; see [`TENANT-AUTHORIZATION.md`](TENANT-AUTHORIZATION.md)).
