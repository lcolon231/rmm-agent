# NodeLink RMM — Storage growth, retention, and capacity

This document defines how every persistent or file-backed data class is bounded,
what is observable, and what happens when a limit is reached (issue #114). It is
the deployment-facing companion to the enforcement code in
`server/app/core/retention.py` and the `GET /api/v1/storage/status` endpoint.

The governing rule: **retention never breaks audit accountability.** Audit
events, Merkle anchors, and anchor-publication receipts are append-only and are
**never** pruned by any automated job, so hash-chain and external-anchor
verification stay reproducible over the full history regardless of retention
settings. The pruners physically do not target those tables.

## Data classes and policy

| Data class | Storage | Growth driver | Policy | Bounded by |
|---|---|---|---|---|
| Agent service logs | Endpoint disk (`%ProgramData%\NodeLink\logs`) | Agent activity | Size-rotated: 10 MB × 5 files | Agent (built in) |
| Server application logs | Server host / stdout | Request volume | Rotate via the platform (systemd-journald limits or `logrotate`) | Deployment |
| Heartbeats / telemetry | DB (`heartbeats`) | Agents × heartbeat rate | Pruned after `telemetry_retention_days` (default 30), per tenant overridable (#88) | `retention.prune_expired` |
| Command results (output) | DB (`commands.stdout/stderr`) | Command volume × output size | Per-stream capture cap (256 KiB/384 KiB); **text** cleared after `command_output_retention_days` (default 90), row + metadata kept | Agent cap + retention |
| Command rows (metadata, incl. scheduled-task runs) | DB (`commands`) | Command volume | Retained by default (`command_record_retention_days` = 0); a platform default or tenant policy may delete **terminal** rows by age, floor 30 days (#88) | Observability + tenant retention |
| Inventory history | DB (`agent_inventory_snapshots`) | Section changes | Newest `inventory_history_per_section` (default 50) kept per agent/section; the newest is never deleted; tenant overridable (#88) | `retention.prune_expired` |
| Alerts and alert history | DB (`alerts`, `alert_events`, `alert_observations`) | Monitoring | Retained by default (`alert_retention_days` = 0); **resolved** alerts deletable by resolution age, floor 30 days (#88) | Tenant retention |
| Notification deliveries | DB (`alert_email_*`, `alert_webhook_*`) | Alert transitions × recipients | Retained by default (`notification_retention_days` = 0); **terminal** deliveries deletable by age, floor 7 days (#88) | Tenant retention |
| Support chat transcripts | DB (`support_messages`, `support_conversations`) | Endpoint-user conversations | Messages **and** the conversation row deleted `support_chat_retention_days` (default 30) after the conversation **closes**; open conversations are never pruned. Lifecycle audit events are kept ([`SUPPORT-CHAT.md`](SUPPORT-CHAT.md)) | `retention.prune_expired` |
| Relay forward receipts (replay guard) | DB (`relay_forward_receipts`) | Relayed requests | Deleted after `relay_receipt_retention_days` (default 7, minimum 1, which always exceeds the accepted skew + forward-age window) | `retention.prune_expired` |
| Audit events | DB (`audit_events`) | Audited actions | **Never pruned** (compliance chain) | Observability only |
| Merkle anchors + receipts | DB (`audit_anchors`, `anchor_publications`) | Anchor cadence | **Never pruned**; unpublished backlog is alerted | Observability + lag alert |
| Retained evidence packages | Evidence vault (`filesystem` or S3 Object Lock) + DB ledger (`evidence_vault_records`, `evidence_legal_holds`) | Store requests | **Never pruned automatically.** Each package carries a retention date (floor `evidence_vault_retention_days`; a tenant policy may set a longer default for new packages, #88); disposal is an explicit admin action refused under legal hold or before expiry ([`EVIDENCE-VAULT.md`](EVIDENCE-VAULT.md)) | Explicit disposal only |
| Encrypted backups | Off-host (operator-managed) | Backup schedule | Pruned **only** after verified off-host retention + key custody (manual) | Operator policy |
| Host disk | Server filesystem | All of the above | Free-space threshold alert | Observability |

### Why command output is *cleared*, not deleted

Deleting a command row would erase operator-visible history and diverge from the
audit log. Instead, past `command_output_retention_days` the heavy `stdout`/
`stderr` **text** is set to NULL while the row keeps its accountability metadata
(exit code, truncation flags, total byte counts, timestamps). The
`command.completed` audit event — which never held the output — is untouched.

`query_event_log` results (issue #58) are metadata-only — structured `<System>`
fields with no message text or `EventData` — and are stored in the same
`commands.stdout` column, so they inherit `command_output_retention_days` with no
separate retention clock. A future message-body feature would require a distinct,
shorter retention clock for the sensitive body; that is out of scope for the
metadata-only v1. See [`EVENT-LOG-ACCESS.md`](EVENT-LOG-ACCESS.md).

### Why support chat transcripts are *deleted*, not cleared

A support chat transcript (issue #237) is free text typed at an endpoint and can
incidentally contain PHI. Unlike a command row, the conversation row itself holds
no metadata that the audit chain lacks. Its accountability record is the
`support_chat.*` lifecycle events, which never held a message body. So past
`support_chat_retention_days` after close, the messages are deleted and then the
emptied conversation row is deleted. Only closed conversations qualify. See
[`SUPPORT-CHAT.md`](SUPPORT-CHAT.md) for why the default is 30 days.

## Tenant-specific retention (issue #88)

Each tenant (client) may override the platform retention for its own data. This
is a control designed for regulated deployments. It does not by itself make any
deployment compliant.

### Categories

| Category (`API field`) | Unit | Data it governs | Platform default setting | Floor / ceiling settings (defaults) |
|---|---|---|---|---|
| `telemetry_days` | days | Heartbeats of the tenant's agents | `telemetry_retention_days` (30) | `retention_min_telemetry_days` (1) / `retention_max_telemetry_days` (3650) |
| `command_output_days` | days | Command stdout/stderr **text**, cleared after completion | `command_output_retention_days` (90) | `retention_min_command_output_days` (1) / `retention_max_command_output_days` (3650) |
| `command_record_days` | days | Whole **terminal** command rows (succeeded/failed/expired) by creation age. Scheduled-task runs are command rows, so this is also task run history. | `command_record_retention_days` (**0**) | `retention_min_command_record_days` (30) / `retention_max_command_record_days` (3650) |
| `inventory_history_per_section` | count | Snapshots kept per agent and section; the newest is never deleted | `inventory_history_per_section` (50) | `retention_min_inventory_history_per_section` (1) / `retention_max_inventory_history_per_section` (1000) |
| `alert_days` | days | **Resolved** alerts by resolution age, with their events, observations, and deliveries | `alert_retention_days` (**0**) | `retention_min_alert_days` (30) / `retention_max_alert_days` (3650) |
| `notification_days` | days | **Terminal** email/webhook deliveries (sent/delivered/failed/suppressed) and their attempts, by creation age | `notification_retention_days` (**0**) | `retention_min_notification_days` (7) / `retention_max_notification_days` (3650) |
| `evidence_default_days` | days | Default `retention_days` for **new** evidence vault records | `evidence_vault_retention_days` (2555) | the vault's own floor / `evidence_vault_max_retention_days` |

The following are **not** tenant-configurable:
- Audit events, anchors and receipts. They are never pruned.
- Check results, support chat, assistant history and relay receipts. These keep their global settings.

### Inheritance, bounds and states

The effective value of each category is resolved in order:
1. The tenant override, if one is set.
2. Otherwise the platform default.
3. Then, **at enforcement time**, the value is clamped into the platform floor and ceiling.

`0` means *keep forever*. It is treated as the longest possible retention:
- It always satisfies a floor.
- It is accepted only when the category's ceiling is `0` (no ceiling).
- `evidence_default_days` cannot be `0`.

Ceilings bound tenant overrides only. At startup, a positive platform default below its floor, or a ceiling below its floor, stops the server (fail closed).

`GET` reports a `source` for every category:

| `source` | Meaning |
|---|---|
| `default` | No override; the platform default applies |
| `tenant` | The tenant override applies as saved |
| `floor` | The override is below a floor raised after it was saved; the floor applies |
| `ceiling` | The override exceeds a ceiling lowered after it was saved; the ceiling applies |

`pruning_suspended: true` means a tenant-wide legal hold is active and nothing of the tenant's is pruned.

### API

All three endpoints are under `/api/v1/clients/{client_id}/retention-policy`.

| Method | Authorization | Body | Result |
|---|---|---|---|
| `GET` | global `readonly` + any membership of the tenant | — | Effective policy |
| `PUT` | global `admin` + `client_admin` (or platform admin) + fresh step-up | `expected_version` plus any categories. A full replacement: omitted or `null` categories inherit. Unknown fields are rejected. | Effective policy |
| `DELETE` | same as `PUT` | `{"expected_version": n}` | Effective policy (all inherited) |

`version` starts at `0` (no policy) and increases on every change, including a clear. A version is never reused.

| Status | `detail.code` | When |
|---|---|---|
| 404 | `client_not_found` | Unknown tenant, or one the caller cannot see (no existence oracle) |
| 403 | (role message) / `step_up_required` | Insufficient global or client role, or the step-up is stale for an enrolled operator |
| 409 | `retention_policy_conflict` | `expected_version` is not the current version (lost update prevented) |
| 422 | `retention_below_minimum` / `retention_above_maximum` / `retention_value_invalid` (+ `category`) | Value outside the platform bounds, negative, or `0` where forever is not allowed |
| 422 | (validation) | Unknown field or missing `expected_version` |
| 404 | `retention_policy_not_found` | `DELETE` when the tenant never had a policy |

Each change is audited as `tenant.retention_policy_set` or `tenant.retention_policy_cleared`. The event carries the old and new values aligned with `categories`, and `organization_id` set to the tenant.

### Enforcement, legal hold, and deletion proof

The retention sweep (`retention_sweep_interval_seconds`) handles each tenant in turn:

- **Legal hold.** If a tenant-wide legal hold is active ([`EVIDENCE-VAULT.md`](EVIDENCE-VAULT.md)), the sweep prunes **nothing** for the tenant. That includes the global classes: check results and closed support chat transcripts. The sweep records `retention.purge_suspended` instead. Record-scoped holds protect only their evidence record. Pruning resumes on the first sweep after release.
- **Boundary.** A row is pruned only when it is strictly older than the cutoff. A row exactly at the cutoff is kept.
- **Live data.** Live data is never pruned. This covers:
  - queued, dispatched or running commands
  - open or acknowledged alerts
  - pending, sending or retrying deliveries
  - the newest inventory snapshot of each section
- **Deletion proof.** Each non-empty purge of one table for one tenant appends `retention.purged`. The event records:
  - the category, table and operation (`deleted` or `cleared`)
  - the cutoff or keep-count
  - the policy version and source
  - the row count and dependent-row count
  - `ids_sha256`, which is SHA-256 over the affected primary keys sorted ascending, each followed by `\n`
  - `truncated`

  It contains no content. Anyone holding a list of the deleted ids, for example from a pre-purge export, can recompute the digest. Each sweep ends with `retention.sweep_completed`.
- **Failure.** Each tenant runs in its own database savepoint. If a tenant's purge fails:
  - all of that tenant's work for the sweep is rolled back
  - `retention.purge_failed` is recorded with only the exception class
  - the other tenants continue

  Selection is cutoff-based, so the next sweep retries idempotently.
- **Resource bounds.** Deletes run in id-ordered batches of `retention_batch_size` (5000). At most `retention_max_rows_per_sweep` (1,000,000) rows are deleted per tenant and table per sweep. A capped purge reports `truncated: true`, and the remainder continues on the next sweep.

Audit events are only ever **appended** by the sweep. Existing events, anchors and receipts are never touched, so `verify_chain` and anchor verification still hold.

### Rollout, compatibility, and rollback

- **Migration.** `0049` adds `tenant_retention_policies` and `ix_alerts_state_resolved`. Both are additive and need no backfill. A missing row inherits.
- **Default behaviour.** The new destructive classes default to `0`, so deploying deletes nothing new until an operator sets a platform default or a tenant override.
- **Existing classes.** Telemetry, command output and inventory keep their previous platform defaults, so existing deployments prune exactly as before, now per tenant.
- **Compatibility.** Agents and the dashboard are unaffected. No protocol changes, and there is no dashboard UI in this change (tracked in #311).
- **Rollback.**
  - For a tenant: `DELETE` the policy.
  - For the capability: set the new `*_RETENTION_DAYS` back to `0`.
  - The migration is forward-only (see `docs/ROLLBACK.md`).
  - **Deleted rows are not recoverable** except from backups. That is the point of the minimums and the step-up requirement.

## Configuration

All settings live in `server/app/core/config.py` (environment variables):

| Setting | Default | Meaning |
|---|---|---|
| `telemetry_retention_days` | 30 | Delete heartbeats older than this. `0` disables (unbounded — not recommended). |
| `command_output_retention_days` | 90 | Clear command output text older than this. `0` disables. |
| `support_chat_retention_days` | 30 | Delete support chat transcripts this long after the conversation closes. `0` disables. A minimum-necessary choice, not a regulatory requirement. |
| `relay_receipt_retention_days` | 7 | Delete relay forward receipts older than this (1–365). See [`RELAYS.md`](RELAYS.md). |
| `command_record_retention_days` / `alert_retention_days` / `notification_retention_days` | 0 | Platform defaults for the #88 classes; `0` keeps forever. |
| `retention_min_*` / `retention_max_*` | see below | Platform floors and ceilings on tenant overrides (#88). |
| `retention_batch_size` / `retention_max_rows_per_sweep` | 5000 / 1,000,000 | Per tenant and table batch size and per-sweep cap (#88). |
| `retention_sweep_interval_seconds` | 86400 | How often the retention sweep runs. |
| `retention_disk_path` | `/` | Filesystem whose free space is reported/alerted. |
| `heartbeat_backlog_alert` | 5,000,000 | Alert when total heartbeat rows exceed this. |
| `command_backlog_alert` | 1,000,000 | Alert when total command rows exceed this. |
| `disk_free_alert_bytes` | 1 GiB | Alert when free space on `retention_disk_path` drops below this. |

## Observability

`GET /api/v1/storage/status` (readonly operator) returns per-class counts,
oldest-age, backlog, host disk headroom, and unpublished-anchor lag, each with a
threshold-breach flag, plus a top-level `alert` boolean that is true when any
class has breached. Example shape:

```json
{
  "retention_policy": {"telemetry_retention_days": 30, "command_output_retention_days": 90, "alert_retention_days": 0, "tenant_policies_overridden": 2},
  "heartbeats": {"count": 12000, "oldest_age_seconds": 2400000, "backlog_alert": false},
  "commands": {"count": 300, "with_output": 120, "backlog_alert": false},
  "audit": {"event_count": 900, "oldest_age_seconds": 5000000},
  "anchor_publication": {"backend": "s3", "pending": 0, "oldest_unpublished_age_seconds": null, "lag_alert": false},
  "disk": {"path": "/", "free_bytes": 53687091200, "total_bytes": 107374182400, "free_alert": false},
  "alert": false
}
```

The retention sweeper logs a warning (`[retention] WARNING storage threshold
breached: …`) whenever `alert` is true, so the condition is visible in server
logs as well as on the endpoint. Poll `storage/status` from your monitoring and
alert on `alert == true` (or on any specific class flag).

## Behavior when a limit is reached

- **Retention thresholds** (`*_backlog_alert`, `disk_free_alert_bytes`) are
  **observability**, not enforcement: breaching them raises alert flags and logs
  a warning; they never delete data. Respond by widening capacity or shortening
  retention windows.
- **Disk full:** writes fail at the database/filesystem layer. The audit chain
  is append-only, so a failed append is a failed transaction, not a silent gap.
  Restore headroom (prune telemetry window, extend the volume) and the server
  resumes; no audit event is lost or forged.
- **Anchor publication lag:** surfaced as `anchor_publication.lag_alert` here and
  by the dedicated `GET /audit/publication-status`; see `docs/AUDIT-ANCHORING.md`.

## Capacity planning

Rough per-endpoint sizing at defaults (order-of-magnitude, tune with
`storage/status`):

- Heartbeats: ~1 row/heartbeat. At a 60 s interval and 30-day retention that is
  ~43,000 rows/endpoint steady-state (small, fixed-width rows).
- Command output: bounded by the 256 KiB/384 KiB capture cap per command and by
  `command_output_retention_days`; the dominant term is commands/day × output
  size × 90 days before text is cleared.
- Audit + anchors: grow monotonically (never pruned). Budget for indefinite
  retention; archival/export is future compliance work, not retention.

## Backups

Encrypted backups are off-host and operator-managed (`docs/BACKUP-RESTORE.md`,
`docs/ROLLBACK.md`). Backup pruning is **not** automated here: prune old backups
only after confirming verified off-host retention and key custody for the
window you are required to keep, so a retention action can never destroy the
last recoverable copy.
