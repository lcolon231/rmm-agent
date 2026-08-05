# Alert email notifications

Issue #45 adds configurable email for alert state transitions. The server uses
a provider boundary with Resend as the first adapter; alert evaluation never
calls the provider directly.

## Configuration

Email is disabled by default. Set these server environment variables to enable
it:

```dotenv
EMAIL_ALERT_PROVIDER=resend
EMAIL_ALERT_RESEND_API_KEY=re_...
EMAIL_ALERT_SENDER=NodeLink Alerts <alerts@example.com>
EMAIL_ALERT_RECIPIENTS=oncall@example.com,security@example.com
EMAIL_ALERT_DASHBOARD_BASE_URL=https://rmm.example.com
```

`EMAIL_ALERT_RECIPIENTS` accepts 1–50 comma-separated addresses. Duplicates are
removed. Production startup fails closed when the provider name, credentials,
sender, recipients, dashboard URL, or worker limits are invalid. The API key is
environment-only and is never written to the database, audit chain, logs,
metrics, templates, or API responses. Use a Resend sending-access key and a
sender on a verified domain.

Optional limits and their defaults:

| Variable | Default | Supported |
|---|---:|---:|
| `EMAIL_ALERT_POLL_INTERVAL_SECONDS` | 15 | 1–3600 |
| `EMAIL_ALERT_BATCH_SIZE` | 25 | 1–100 |
| `EMAIL_ALERT_MAX_ATTEMPTS` | 5 | 1–20 |
| `EMAIL_ALERT_BACKOFF_BASE_SECONDS` | 30 | 1–3600 |
| `EMAIL_ALERT_BACKOFF_MAX_SECONDS` | 3600 | 1–86400 |
| `EMAIL_ALERT_CLAIM_TIMEOUT_SECONDS` | 300 | 30–3600 |
| `EMAIL_ALERT_REQUEST_TIMEOUT_SECONDS` | 10 | 1–30 |

## Transition and template contract

Emails are snapshotted for `opened`, `reopened`, `acknowledged`, manual
resolution, automatic recovery, and resolution caused by policy revision,
deletion, or supersession. Assignment and comment-only events do not send
email. An opening/reopening transition inside a matching maintenance window is
recorded as `suppressed` and never sent. A later recovery remains a distinct
transition and may send a closure message.

Templates contain only the check key, endpoint/alert IDs, generation, state,
last result/value, transition time, and optional dashboard link. Values are
HTML-escaped. Check-result detail, operator comments, credentials, and provider
responses are deliberately excluded. The stored snapshot makes every retry use
the same payload.

## Delivery, retries, and idempotency

The alert event and one `alert_email_deliveries` row per recipient commit in the
same transaction. Provider downtime therefore cannot roll back or delay core
alert state. A bounded worker:

1. claims due `pending`/`retrying` rows with `FOR UPDATE SKIP LOCKED`;
2. records an attempt and commits the short claim transaction;
3. calls the provider with no database lock held; and
4. records `sent`, `retrying`, or `failed` plus a sanitized error code.

Network failures, HTTP 408/425/429, 5xx responses, and concurrent idempotency
requests retry with capped exponential backoff. Permanent 4xx validation/auth
failures become `failed` immediately. Expired worker claims return to the queue.
Each provider call uses `alert-email/<delivery UUID>` as the Resend
`Idempotency-Key`; Resend retains keys for 24 hours, while NodeLink's unique
`(alert_event_id, recipient)` constraint prevents duplicate queue rows for the
same transition. An operator can explicitly retry a failed delivery; that
request has its own 16–64 character idempotency key and adds only one new
attempt allowance.

## Visibility and authorization

Readonly-or-higher operators may inspect:

- `GET /api/v1/monitoring/email-alerts/status` — safe configuration flags and
  delivery counts, never key/sender/recipient values; and
- `GET /api/v1/monitoring/alerts/{alert_id}/email-deliveries` — at most 250
  deliveries with masked recipients and append-only attempt history.

Operator-or-higher users may call
`POST /api/v1/monitoring/email-deliveries/{delivery_id}/retry`. The dashboard
alert page exposes the same notification ledger and retry control through a
same-origin server session boundary. Retry audit event
`monitoring_alert_email.retried` stores the recipient only as SHA-256 plus byte
count. Automatic provider attempts are operational history, not human audit
events.

Metrics are exported as `nodelink_alert_email_operations_total` with queued,
sent, retrying, failed, suppressed, recovered-claim, manual-retry, and
configuration-error operations. Logs contain counts and exception class names,
not addresses, provider response bodies, or credentials.

## Migration and rollback

Alembic revision `0019` adds `alert_email_deliveries`,
`alert_email_attempts`, and their status enums, constraints, foreign-key/query
indexes, RLS, and explicit revocation from `PUBLIC`, `anon`, and
`authenticated`. Apply the migration before the new server. No agent protocol
change is required. Deploy with `EMAIL_ALERT_PROVIDER=disabled`, validate the
status endpoint, then enable Resend and send a controlled test alert.

Migrations are forward-only. Rollback disables the provider first, then either
keeps the additive tables while reverting server/dashboard code or restores a
tested pre-`0019` backup with the prior release. Pending rows remain durable
while the provider is disabled and resume when a compatible server is restored.
