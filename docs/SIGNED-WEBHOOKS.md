# Signed monitoring webhooks

NodeLink can notify deployment-owned HTTPS receivers when an alert opens,
reopens, is acknowledged, resolves, or is affected by a policy transition.
The delivery body is versioned and signed with a destination-specific secret.
Comments, alert detail, operator email addresses, credentials, and endpoint
URLs are not included in the payload or delivery history.

## Configure the server

Generate a dedicated 32-byte encryption key and store the base64url value in
the server's secret environment as `WEBHOOK_SECRET_ENCRYPTION_KEY`:

```powershell
python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

Do not reuse `SECRET_KEY` or a command-signing key. NodeLink uses this key only
to AES-GCM encrypt webhook signing secrets at rest. Endpoint creation and secret
rotation fail closed when the key is absent or malformed. Losing it makes
existing secrets undecryptable; restore the old key or rotate every endpoint.

The deployment settings and accepted ranges are:

| Environment variable | Default | Accepted range |
| --- | ---: | ---: |
| `WEBHOOK_POLL_INTERVAL_SECONDS` | 15 | 1–3600 |
| `WEBHOOK_BATCH_SIZE` | 25 | 1–100 |
| `WEBHOOK_MAX_ATTEMPTS` | 5 | 1–20 |
| `WEBHOOK_BACKOFF_BASE_SECONDS` | 30 | 1–3600 |
| `WEBHOOK_BACKOFF_MAX_SECONDS` | 3600 | 1–86400 |
| `WEBHOOK_CLAIM_TIMEOUT_SECONDS` | 300 | 30–3600 |
| `WEBHOOK_REQUEST_TIMEOUT_SECONDS` | 10 | 1–30 |
| `WEBHOOK_DNS_TIMEOUT_SECONDS` | 5 | 1–30 |
| `WEBHOOK_MAX_ENDPOINTS` | 50 | 1–100 |

The payload limit is 64 KiB and response headers are limited to 16 KiB. The
receiver response body is never downloaded.

## Create and operate a destination

Open **Monitoring → Signed webhooks** as an administrator. Enter a name, a
public HTTPS URL, and the alert transitions to send. Copy the generated
`whsec_...` signing secret immediately: it is returned only by create and
rotate responses. After save, the dashboard and API expose only a masked
destination.

Readonly users may inspect destinations and history. Operators may validate a
destination and retry a failed delivery. Only administrators may create,
modify, disable, delete, or rotate destinations. Those mutations and manual
retries are audited without retaining plaintext destinations or secrets.

Validation reports one of four explicit states:

- `valid`: the URL and all current DNS answers are allowed.
- `invalid`: the URL is malformed or violates the destination policy.
- `unavailable`: DNS could not currently be resolved.
- `unsupported`: the hostname resolves to an address NodeLink will not contact.

Destinations must use `https` on port 443, without URL credentials or a
fragment. On every attempt NodeLink resolves all A and AAAA answers, rejects
the complete set if any address is not globally routable, and connects directly
to one validated address while retaining the original hostname for TLS SNI and
certificate verification. Redirects are never followed. This closes the DNS
rebinding window between validation and connection and blocks loopback,
private, link-local, multicast, reserved, and otherwise non-global targets.

## Verify a request

Each request has these headers:

| Header | Meaning |
| --- | --- |
| `X-NodeLink-Webhook-Version` | Payload API version (`2026-08-05`) |
| `X-NodeLink-Event-Id` | Stable alert-event identifier |
| `X-NodeLink-Delivery-Id` | Stable delivery identifier across retries |
| `Idempotency-Key` | `nodelink-webhook/<delivery-id>` |
| `X-NodeLink-Timestamp` | Unix timestamp captured when delivery was queued |
| `X-NodeLink-Signature` | `v1=<lowercase HMAC-SHA256 hex>` |

Compute the signature over the exact received body bytes:

```text
v1.<X-NodeLink-Timestamp>.<raw request body>
```

Use the destination secret as the HMAC-SHA256 key and compare the expected and
received signatures with a constant-time comparison. Reject an unknown version,
an unexpected content type, or a timestamp outside the receiver's replay
window. Record the delivery ID before applying side effects and treat repeats
as success; NodeLink uses at-least-once delivery.

The canonical JSON body contains `api_version`, `delivery_id`, `event_id`,
`event_type`, `occurred_at`, and a bounded `alert` object with identifiers,
severity, state, check key, and timestamps. Receivers should ignore unknown
fields within a known API version and reject unsupported API versions.

## Retries, rotation, and recovery

HTTP 2xx completes a delivery. Network failures, timeouts, HTTP 408/425/429,
and HTTP 5xx retry with exponential backoff capped by the configured maximum.
Other HTTP failures are terminal. Every attempt is recorded with a sanitized
error code and optional HTTP status; response bodies, destination URLs, and
secret material are not stored in history.

Rotating a destination returns a new one-time secret for future events. Queued
deliveries remain bound to their original encrypted secret version, so an
in-flight retry keeps the same signature. Disabling or deleting a destination
suppresses its queued deliveries. A manual retry reopens a terminal failed
delivery without changing its delivery ID or secret version.

If a worker stops after claiming work, the claim timeout returns that delivery
to the queue. The database uniqueness boundary on destination plus alert event
prevents duplicate queue rows.

## Rollout and rollback

Back up the database and encryption key, deploy the server migration, set the
encryption key, then create and validate one test destination before enabling
production receivers. Monitor pending, retrying, failed, and delivered counts
on the webhook page.

The migration is forward-only. To stop outbound delivery without losing
history, disable destinations or stop the webhook worker and deploy a forward
fix. Restore an exact pre-migration backup only as part of the repository's
documented release rollback procedure; do not run an Alembic downgrade.
