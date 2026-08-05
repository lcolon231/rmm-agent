# Monitoring alert state

Issues #43 and #44 turn revision-pinned check results into one durable alert
identity per `(agent_id, policy_id, check_key)`, then add the authorized
technician lifecycle around it. Automatic transitions and technician actions
share the same row lock, version counter, and append-only history.
Issue #45 consumes these immutable transitions through the durable email
boundary documented in [`ALERT-NOTIFICATIONS.md`](ALERT-NOTIFICATIONS.md).

## State contract

| Current state | New result | Resulting behavior |
|---|---|---|
| No alert | `ok` | No alert is created. |
| No alert | `warning`, `critical`, or `unknown` | Create the identity in `open`, generation 1, occurrence 1. `unknown` requires attention and is never treated as healthy. |
| `open` | non-`ok` | Keep the same alert and increment the current and lifetime occurrence counters. |
| `open` or `acknowledged` | `ok` | Automatically move to `resolved` with reason `automatic_recovery`. |
| `resolved` | non-`ok` | Reopen the same identity, increment its generation, and reset the current incident's occurrence count to 1. |
| Any | older result | Preserve the newer state; retain the observation as `out_of_order` evidence. |

An operator-or-higher technician may move `open` to `acknowledged`. A manual
resolution may move either `open` or `acknowledged` to `resolved`; a subsequent
non-healthy result reopens the same identity as a new generation. Assignment
and comments do not change the state.

Every result applied to an existing alert is represented by one
`alert_observations` row keyed by the check-result ID. This makes retry handling
exactly once. The row has a foreign key to `check_results`, so the existing
newest-N result retention also bounds observation storage.

## Concurrency and policy changes

- The database unique constraint is the final authority for alert identity.
- PostgreSQL conflict-safe insertion and a row lock serialize concurrent
  evaluations for the same identity.
- `(evaluated_at, result_id)` is the deterministic ordering key. A delayed
  older result can add evidence and lifetime occurrence count but cannot recover
  or overwrite newer state.
- A concurrent retry with the same result ID is acknowledged as a duplicate
  after its stored payload is checked for an exact match.
- Removing or disabling a check resolves that policy's active alert with
  `policy_revised`; deleting the policy uses `policy_deleted`.
- When a different effective policy begins supplying the same endpoint/check,
  the old policy identity resolves with `policy_superseded` before the new one
  is evaluated.
- Every technician request carries an alert `expected_version` and a unique
  request ID. The row is locked before validation; a stale version returns 409,
  while an exact request-ID retry returns the already-committed alert without
  appending duplicate history or audit evidence.
- Automatic recovery/reopen and technician transitions increment the same
  version, so an automatic/manual race has one serialized winner and the loser
  must refresh before retrying.

Policy IDs are preserved as strings rather than cascading foreign keys. A
deleted policy therefore cannot erase alert evidence.

## Maintenance windows

Checks still evaluate and alert state still changes during maintenance. A
matching global/client/site/agent window records `suppression_window_id` and
the latest applicable `suppressed_until` on each failing occurrence. This keeps
the incident visible while giving #45/#46 notification delivery an explicit,
server-derived suppression boundary. A healthy result clears suppression
metadata.

## API and authorization

Readonly-or-higher operators may use:

- `GET /api/v1/monitoring/alerts` with bounded filters for agent, policy,
  check key, state, and latest result status;
- `GET /api/v1/monitoring/alerts/{alert_id}` for current state, at most 100
  retained observations, and the most recent 200 lifecycle events.

Operator-or-higher technicians may use:

- `GET /api/v1/monitoring/alert-assignees` for active assignment targets;
- `POST /api/v1/monitoring/alerts/{alert_id}/acknowledge`;
- `POST /api/v1/monitoring/alerts/{alert_id}/assign`;
- `POST /api/v1/monitoring/alerts/{alert_id}/comments`; and
- `POST /api/v1/monitoring/alerts/{alert_id}/resolve`.

Email configuration status, per-alert delivery history, and role-gated manual
retry APIs are documented in [`ALERT-NOTIFICATIONS.md`](ALERT-NOTIFICATIONS.md).

Action comments are trimmed, limited to 2,000 characters, scrubbed for
credential-shaped text before storage, and represented in the tamper-evident
audit chain only by a SHA-256 digest and byte count. The operational
`alert_events` row retains the scrubbed comment, actor identity, generation,
state transition, assignment snapshot, request ID, and timestamp. Read-only
dashboard users can inspect this history but cannot mutate it. Dashboard POST
handlers require same-origin requests and keep the operator bearer token in the
server-managed session boundary.

The server derives agent identity for result ingestion and never accepts it in
the result body. Automatic state changes remain operational evidence;
technician acknowledgement, assignment, comment, and manual-resolution actions
also emit redacted `monitoring_alert.*` audit events. Transition and occurrence
counters are exported through the existing monitoring metrics family.

## Migration, rollout, and rollback

Alembic revision `0017` creates `alerts`, `alert_observations`, and the
`alertstate` enum. Revision `0018` adds assignment, acknowledgement, and version
fields plus `alert_events`; every pre-existing alert receives a deterministic
`state_imported` baseline event. Existing check results remain intact. On
PostgreSQL, all three public-schema alert tables enable RLS and revoke direct
Data API access from `anon` and `authenticated`; `alert_events` also revokes
`PUBLIC`. Revision `0019` adds the durable email queue and append-only provider
attempt history with the same Data API isolation. NodeLink's authorized
FastAPI service remains the data boundary.

Deploy through revision `0019`, then the server and dashboard. No agent change is
required. A new server refuses to start against an older schema; the old server
ignores the additive columns/table during a staged rollout. NodeLink migrations
are forward-only. Rollback therefore restores a tested pre-`0018` database
backup together with the previous server/dashboard release, or uses a reviewed
forward-fix migration.
