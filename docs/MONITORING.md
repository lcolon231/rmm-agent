# Monitoring checks

Issue #42 implements the first executable monitoring checks on top of the
versioned policy and result foundation from #41. This document defines the
runtime contract. Issue #43's alert-state extension is documented in
`docs/ALERTS.md`; technician actions and notifications remain separate issues.

## Data flow

1. An active agent sends its normal authenticated heartbeat.
2. The heartbeat response includes the agent's resolved checks, each pinned to
   the policy and append-only revision that supplied it. Offline checks are not
   sent because an endpoint cannot determine that it is unreachable.
3. The agent evaluates only checks whose configured interval has elapsed. It
   saves results and hysteresis state to `monitoring_state.json` before upload.
4. The agent posts at most 100 results per request to
   `POST /api/v1/agents/me/monitoring/results`.
5. The server authenticates the agent, verifies every check key and policy
   revision against its current effective policy, rejects stale/future or
   malformed batches atomically, and stores accepted rows append-only.
6. Agent-generated 128-bit result IDs are idempotency keys. A lost response is
   retried with the same IDs and acknowledged as a duplicate without creating
   another row.
7. Each accepted revision-pinned result updates one deduplicated
   policy/endpoint/check alert identity. Failure/unknown results open or update
   it, healthy results recover it, and a later failure reopens a new generation.
   Patch-age `unknown` results are the exception: they retain unavailable
   evidence without opening an alert that could be mistaken for an old patch.

When a successful heartbeat replaces or removes a policy revision, the agent
discards queued results pinned to the superseded assignment before evaluating
the new one. This prevents an intentionally rejected old revision from blocking
the bounded outbox indefinitely.

The agent outbox is capped at 256 results. A full outbox pauses new evaluations
instead of discarding older evidence. One evaluation pass performs at most 32
distinct platform probes; additional checks report `unknown` with
`probe_budget_exhausted`.

## Supported checks

| Type | Input | Passing state | Failure/unavailable behavior |
|---|---|---|---|
| `offline` | Server-observed age of `last_seen_at` | Age does not breach the configured numeric threshold | Never checked in is `unknown`; overdue age is warning/critical. Evaluated by the server heartbeat sweeper. |
| `patch_age` | Age in days of the newest installed update in stored `windows_updates` inventory | Newest install age does not breach the rising numeric threshold | Missing/unusable inventory, no installed updates or timestamps, and timestamps more than five minutes in the future are `unknown` and do not open an alert. Evaluated by the server heartbeat sweeper no more often than hourly. |
| `cpu` | Current telemetry CPU percentage | Numeric threshold does not breach | Missing or stale sample is `unknown`. |
| `memory` | Current telemetry memory percentage | Numeric threshold does not breach | Missing or stale sample is `unknown`. |
| `disk` | Usage percentage for configured `mount_point` | Numeric threshold does not breach | Missing volume, failed probe, or stale system-drive sample is `unknown`. |
| `service` | Windows service named by `service_name` | Service state is `running` | Absent or non-running is `critical`; probe failure/unsupported platform is `unknown`. A legacy numeric threshold is accepted for old #41 revisions but ignored. |
| `reboot_pending` | Windows reboot-required registry sources | No reboot is pending | Pending is `critical`; failed/unsupported probe is `unknown`. Which sources are set rides along in the result detail (agent v0.1.8+) without affecting status. |

The earlier `uptime` policy contract remains compatible and uses the same
numeric evaluator, although it is not one of issue #42's six initial checks.

### Patch-age inventory prerequisite

`patch_age` is meaningful only when endpoints have a recurring `scan_updates`
schedule. The `windows_updates` section is populated by that on-demand command,
not by the heartbeat inventory path. Without a successful scan, the check
records `unknown` with `no_update_inventory` and intentionally opens no alert.
After each scan, the server evaluates the newest non-null `installed_on` value;
an empty installed list and a list whose timestamps are all null remain distinct
unknown states for troubleshooting.

Patch age and patch-compliance staleness answer different questions.
`patch_age` measures how long ago the endpoint installed its newest update;
`patch_compliance` state `stale` means the update scan itself is old. A freshly
scanned endpoint can have old installed patches, and a recently patched endpoint
can have stale scan evidence. Keep both signals visible rather than treating one
as a substitute for the other. See `docs/PATCH-COMPLIANCE.md` for the compliance
state contract.

### Pending-restart update correlation

Opening a `reboot_pending` alert correlates it with the endpoint's latest stored
`windows_updates` inventory. The detail response includes missing updates that
were individually flagged `reboot_required`, plus up to ten updates installed
inside the seven-day window preceding the alert. It also includes the inventory
scan and receipt timestamps so technicians can judge evidence freshness.

This read path never dispatches `scan_updates`; correlation is available only
from inventory already stored by a prior scan. A missing snapshot therefore
produces no cause block. A deleted policy revision also produces no cause block
because the server can no longer safely resolve the alert's check type.

Inventory timing is supporting evidence, not a causal verdict. In particular,
agents deployed before reboot-source reporting have no `sources` key in their
result detail. The dashboard labels those alerts "Cause unavailable" even when
it can list nearby update activity. Absence of `sources` must never be treated
as evidence that the restart is not update-related. The alert's lifecycle,
severity, suppression, and notification behavior are unchanged.

### Reboot source reporting

Agent v0.1.8 and later report which of the three reboot-required registry
sources are set, so the server can state the cause categorically instead of
inferring it from update timing. The `reboot_pending` result detail carries:

```json
{
  "check_type": "reboot_pending",
  "reason": "reboot_pending",
  "sources": {
    "component_based_servicing": true,
    "windows_update": true,
    "pending_file_rename": false
  },
  "pending_file_rename_count": 0
}
```

The alert detail route turns those flags into `reboot_cause.cause`:
`update_caused` when `windows_update` is set, `not_update_caused` otherwise,
and `unknown` when the flags are absent or unusable. Component-Based Servicing
and a queued file rename are reported and rendered, but neither of them means
an installed update is waiting on a restart, so neither produces
`update_caused`.

**Status does not move.** Any source being set is still pending and still
`critical`, no source set is still `ok`, and a failed probe is still `unknown`
with `reboot_probe_failed`. The flags are evidence carried alongside a decision
that is made exactly as it was before.

`pending_file_rename_count` counts queued rename operations. **The paths behind
it are deliberately never collected**, on the endpoint or anywhere downstream:
`PendingFileRenameOperations` entries routinely contain user names
(`C:\Users\<name>\...`) and installer temp paths that disclose internal
software, and result detail fans out over alert email and third-party webhooks,
so a path here would leave the tenant boundary. Knowing that a file-rename
reboot is pending is the actionable fact; the file list does not change what a
technician does. The count is best-effort and never decides status — a failed
count query leaves it at `0` (or `null` server-side) with the source flags
intact.

Numeric checks evaluate critical before warning and support `gt`, `gte`, `lt`,
and `lte`. CPU, memory, and disk results must remain in the inclusive 0–100
range at ingestion. An `unknown` result is never treated as `ok`.

## Cadence, hysteresis, and recovery

The heartbeat remains the transport cadence. A check is due only when its own
`interval_seconds` has elapsed, so a short check interval cannot make the agent
poll faster than its server-provided heartbeat interval. Telemetry older than
twice the check interval, with a two-minute minimum, becomes `unknown`.

`raise_samples` consecutive higher-severity samples are required before an
alarm state becomes stable. `clear_samples` consecutive lower-severity samples
are required before recovery or de-escalation. Pending transitions and the raw
status are included in bounded result detail so technicians can distinguish a
debounced transition from missing data. The counters and last-evaluation times
survive restarts in `monitoring_state.json`.

## Security and compatibility

- Only an active authenticated agent can submit its own results. Quarantined
  agents receive no checks and cannot submit results; revoked credentials fail
  authentication.
- The server owns `agent_id`; it is never accepted from the request body.
- Result detail is finite JSON capped at 16 KiB and result batches/check sets
  are capped at 100.
- Evaluation timestamps require a timezone, may be at most five minutes in the
  future, and may be no older than three check intervals (five-minute minimum).
- Policy revisions are delivered in heartbeat responses. Unknown fields remain
  additive, so old agents ignore checks and new agents connected to an old
  server evaluate none. Roll out the server before the agent.
- Rolling the server back while a new agent has pending monitoring results can
  make result upload unavailable; command processing remains independent, and
  the bounded outbox retries after the compatible server returns.

Check results and automatic alert transitions are operational evidence and
metrics, not operator audit events. Policy and maintenance-window mutations
remain role-gated and audited. Matching maintenance windows annotate failing
alert occurrences with a server-derived suppression deadline while retaining
the visible incident. Operator-or-higher technicians can acknowledge, assign,
comment on, and manually resolve alerts through version-checked, idempotent
requests. These actions append scrubbed immutable lifecycle history and
digest-only tamper-evident audit records; automatic recovery and reopen use the
same row lock and version counter. The live dashboard exposes the active queue,
technician controls, lifecycle history, and recent check evidence. See
`docs/ALERTS.md` for the complete state, authorization, and rollout contract.
