# Monitoring alert state

Issue #43 turns revision-pinned check results into one durable alert identity per
`(agent_id, policy_id, check_key)`. It implements automatic state and
occurrence handling only. Technician acknowledgement, assignment, comments,
manual resolution, and immutable actor history are issue #44.

## State contract

| Current state | New result | Resulting behavior |
|---|---|---|
| No alert | `ok` | No alert is created. |
| No alert | `warning`, `critical`, or `unknown` | Create the identity in `open`, generation 1, occurrence 1. `unknown` requires attention and is never treated as healthy. |
| `open` | non-`ok` | Keep the same alert and increment the current and lifetime occurrence counters. |
| `open` or `acknowledged` | `ok` | Automatically move to `resolved` with reason `automatic_recovery`. |
| `resolved` | non-`ok` | Reopen the same identity, increment its generation, and reset the current incident's occurrence count to 1. |
| Any | older result | Preserve the newer state; retain the observation as `out_of_order` evidence. |

`acknowledged` is reserved in the versioned database contract so #44 can add
the authorized action without a mixed-version enum break. #43 never produces
that state.

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
- `GET /api/v1/monitoring/alerts/{alert_id}` for current state plus at most 100
  retained observations.

The server derives agent identity for result ingestion and never accepts it in
the result body. Alert state is operational evidence, not an operator audit
event. Policy and maintenance-window mutations remain in the tamper-evident
audit chain, while alert transition/occurrence counters are exported through
the existing monitoring metrics family.

## Migration, rollout, and rollback

Alembic revision `0017` creates `alerts`, `alert_observations`, and the
`alertstate` enum. There is no backfill: existing check results remain intact
and new accepted results begin state tracking after deployment. On PostgreSQL,
both new public-schema tables enable RLS and revoke direct `anon` and
`authenticated` access; NodeLink's authorized FastAPI service remains the data
boundary.

Deploy the migration and server together; no agent or dashboard change is
required. NodeLink migrations are forward-only. Rollback therefore restores a
tested pre-`0017` database backup together with the previous server release, or
uses a reviewed forward-fix migration.
