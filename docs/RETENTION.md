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
| Heartbeats / telemetry | DB (`heartbeats`) | Agents × heartbeat rate | Pruned after `telemetry_retention_days` (default 30) | `retention.prune_expired` |
| Command results (output) | DB (`commands.stdout/stderr`) | Command volume × output size | Per-stream capture cap (256 KiB/384 KiB); **text** cleared after `command_output_retention_days` (default 90), row + metadata kept | Agent cap + retention |
| Command rows (metadata) | DB (`commands`) | Command volume | Retained (accountability); observable backlog | Observability |
| Audit events | DB (`audit_events`) | Audited actions | **Never pruned** (compliance chain) | Observability only |
| Merkle anchors + receipts | DB (`audit_anchors`, `anchor_publications`) | Anchor cadence | **Never pruned**; unpublished backlog is alerted | Observability + lag alert |
| Encrypted backups | Off-host (operator-managed) | Backup schedule | Pruned **only** after verified off-host retention + key custody (manual) | Operator policy |
| Host disk | Server filesystem | All of the above | Free-space threshold alert | Observability |

### Why command output is *cleared*, not deleted

Deleting a command row would erase operator-visible history and diverge from the
audit log. Instead, past `command_output_retention_days` the heavy `stdout`/
`stderr` **text** is set to NULL while the row keeps its accountability metadata
(exit code, truncation flags, total byte counts, timestamps). The
`command.completed` audit event — which never held the output — is untouched.

## Configuration

All settings live in `server/app/core/config.py` (environment variables):

| Setting | Default | Meaning |
|---|---|---|
| `telemetry_retention_days` | 30 | Delete heartbeats older than this. `0` disables (unbounded — not recommended). |
| `command_output_retention_days` | 90 | Clear command output text older than this. `0` disables. |
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
  "retention_policy": {"telemetry_retention_days": 30, "command_output_retention_days": 90},
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
