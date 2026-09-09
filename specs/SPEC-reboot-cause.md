# Spec: reboot-cause

Module id: `reboot-cause` (see `specs/CAPABILITY-MAP-patch-alerting.md`)

## Objective

Make a pending-restart alert say **why** the restart is pending, so a technician
can tell "Windows Update installed patches and needs a reboot" apart from "a
file-rename operation is queued" without remoting into the machine.

**What already works.** The `reboot_pending` check ships end to end today: the Go
probe (`agent/internal/monitoring/probe_windows.go:54`), the policy schema
(`server/app/schemas/monitoring.py:159`), the alert lifecycle, and the alerts
page. A `critical` result already fires an alert with full
acknowledge/assign/resolve, maintenance-window suppression, and email/webhook
fan-out. **This module adds no new alert.**

**What is missing.** The probe collapses three distinct registry sources into a
single boolean:

```
HKLM:\...\Component Based Servicing\RebootPending
HKLM:\...\WindowsUpdate\Auto Update\RebootRequired
HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager!PendingFileRenameOperations
```

Only the second means "an update needs a restart". Today all three produce the
same opaque `reboot_pending` alert, and `CheckResult.detail` is not exposed to
the dashboard by any endpoint at all.

**User story.** As a technician triaging a restart alert, I open it and see
which reboot sources are set and which recently installed KBs flagged
`reboot_required`, so I know whether this is patch fallout worth scheduling a
reboot window for.

## Tech Stack

- Agent: Go (`windows/amd64` supported; `linux/amd64`, `darwin/arm64` dev only)
- Server: Python 3, FastAPI, SQLAlchemy 2 (async), Pydantic v2
- Dashboard: Next.js 16.2.12, React 19.2.4, TypeScript 5, Node >= 24

## Commands

```
# Agent
cd agent
go vet ./...
go build ./...
go test ./...

# Server
cd server
pip install -r requirements.txt pytest pytest-asyncio httpx aiosqlite "moto[s3]"
python scripts/gen_command_keys.py     # once, before the first test run
pytest -q
pytest -q tests/test_reboot_cause.py

# Dashboard
cd dashboard
npm ci && npm run lint && npm run typecheck && npm test && npm run build
```

## Project Structure

```
agent/internal/monitoring/probe.go            -> RebootPending signature: sources
agent/internal/monitoring/probe_windows.go    -> report which sources are set
agent/internal/monitoring/probe_other.go      -> stub returns no sources
agent/internal/monitoring/evaluator.go        -> carry sources into result detail
agent/internal/monitoring/evaluator_test.go   -> extend
server/app/schemas/monitoring.py              -> AlertDetailOut.last_result_detail, reboot_cause
server/app/api/management.py                  -> populate both on the alert-detail route
server/app/core/monitoring.py                 -> reboot_cause derivation from inventory
server/tests/test_reboot_cause.py             -> new
dashboard/src/lib/monitoring-core.ts          -> parse the new fields
dashboard/src/app/alerts/[alertId]/page.tsx   -> render the cause panel
dashboard/test/monitoring-core.test.ts        -> extend
docs/MONITORING.md, docs/ALERTS.md            -> document the cause payload
```

No database migration: `CheckResult.detail` is an existing JSON column, and the
cause is derived at read time from data already stored.

## Design

Two independent evidence sources, layered so each is useful without the other,
and **shipped in two releases**: layer 2 first (server-only, works against the
fleet as it stands today), layer 1 second (needs an agent release).

### Layer 1 — authoritative source flags (agent) — ships second

Change `RebootPending` to return which sources are set rather than a bare bool:

```go
// RebootSources reports which Windows reboot-required signals are set.
// Distinguishing them is the whole point: only WindowsUpdate means an
// installed update is waiting on a restart.
type RebootSources struct {
	ComponentBasedServicing bool
	WindowsUpdate           bool
	PendingFileRename       bool
}
```

The evaluator's status logic is unchanged — pending is still `critical`, and any
source being set is still pending — so no alert changes state as a result of
this work. The sources ride along in the result `detail`:

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

`pending_file_rename_count` is how many `PendingFileRenameOperations` entries
exist — **a count only, never the paths** (see Resolved Decisions).

**Mixed-version behavior.** An agent that has not been updated sends no
`sources` key. The server must treat an absent `sources` as unknown-cause and
render "Cause unavailable — agent predates cause reporting", never as "no
update-related cause". This is the single most important correctness rule in the
module; a stale agent must not produce a confidently wrong triage answer.

### Layer 2 — KB attribution (server, derived) — ships first

At alert-detail read time, for an alert whose `check_key` resolves to a
`reboot_pending` check, derive a `reboot_cause` block from the endpoint's latest
`windows_updates` inventory snapshot:

- `reboot_flagged_updates`: entries in `missing[]` with `reboot_required == true`
- `recent_installs`: `installed[]` entries whose `installed_on` falls between
  the alert's `first_opened_at` minus a lookback window (default 7 days) and now,
  newest first, bounded to 10 entries
- `system_reboot_required`: the snapshot's top-level `reboot_required`
- `scanned_at`, `snapshot_received_at`: so the operator can judge the evidence

This layer is **correlational, not causal** — it says "these updates were
installed around when the reboot flag appeared", and the payload and UI must be
worded that way. Layer 1 is what states the cause categorically.

Shipping this layer alone is worth a release: it needs no agent change, so it
lands for the whole fleet at once, and "three updates installed in the last two
days, two of them flagged reboot-required" answers the operator's real question
most of the time. Until layer 1 lands, every alert renders in the
cause-unavailable state below with the correlated list beneath it — which is
also exactly how a pre-update agent renders permanently. That makes the
cause-unavailable path the *default* path in release one, so it is exercised by
real use before it becomes an edge case.

### Exposing it: `AlertDetailOut` only

`AlertOut` carries no `detail` today and `CheckResult.detail` has no API surface
at all. Add to `AlertDetailOut` (the single-alert route, not the list):

```python
last_result_detail: dict | None = None   # CheckResult.detail for last_result_id
reboot_cause: RebootCauseOut | None = None  # derived; None for non-reboot checks
```

Detail-route only, deliberately: the alerts list already fans out over every
open alert, and joining inventory per row would turn a list render into an N+1
inventory scan.

## Code Style

Server code follows the surrounding module: `from __future__ import annotations`,
SPDX header on new files, explicit `None` returns over exceptions for
"not applicable", comments that justify a rule rather than restate the code.

```python
def derive_reboot_cause(
    snapshot: AgentInventorySnapshot | None,
    detail: dict | None,
    since: datetime,
) -> RebootCause | None:
    """Correlate a pending reboot with recent update activity.

    Returns None when there is nothing to say. An absent ``sources`` key means
    the agent predates cause reporting — that is reported as unknown, never as
    "no update-related cause", because a stale agent must not be able to produce
    a confidently wrong triage answer.
    """
```

Go code matches `agent/internal/monitoring/`: build-tagged platform files, a
`_other.go` stub for every `_windows.go`, table-driven tests.

## Testing Strategy

| Level | Cases |
|---|---|
| Go unit | Each registry source alone sets exactly its own flag; all three set; none set is `ok`; probe failure is `unknown` with `reboot_probe_failed`; `probe_other.go` stub returns unsupported |
| Go evaluator | Status remains `critical`/`ok`/`unknown` identically to today (regression guard: this module must not move any alert) |
| Server unit | `derive_reboot_cause` with: no snapshot; snapshot with `reboot_required` true and flagged missing updates; installs inside vs. outside the lookback window; more than 10 recent installs truncates to 10, newest first |
| Server mixed-version | Detail with no `sources` key yields unknown-cause, not "no update cause" |
| Server API | `AlertDetailOut` carries `last_result_detail` and `reboot_cause` for a reboot alert; both `None` for a `cpu` alert; the alerts *list* response is byte-identical to before |
| Dashboard | `monitoring-core` parses and rejects malformed cause payloads; the detail page renders the three states — update-caused, non-update-caused, cause unavailable |

Add any new dashboard test file to the explicit list in `dashboard/package.json`
or `npm test` will silently skip it.

## Boundaries

**Always**
- Preserve the existing `reboot_pending` status logic exactly — this module changes what an alert *says*, never whether it fires
- Treat a missing `sources` key as unknown cause
- Word the KB attribution as correlation, in both payload naming and UI copy
- Keep a `_other.go` stub in step with every `_windows.go` change, so `go build ./...` passes on dev targets

**Ask first**
- Surfacing `PendingFileRenameOperations` paths in any form
- Any change to when a `reboot_pending` alert opens, resolves, or changes severity
- Adding the cause to `AlertOut` / the alerts list route (N+1 inventory scan)
- Adding the cause to email or webhook notification payloads
- Bumping the inventory or monitoring protocol schema version

**Never**
- Present the correlational KB list as the definitive cause
- Let a pre-update agent's silence read as "not update-related"
- Trigger an update scan from the alert-detail read path
- Put registry paths, hostnames, or user names from `PendingFileRenameOperations` into the payload unredacted

## Success Criteria

1. A Windows endpoint with only `WindowsUpdate\Auto Update\RebootRequired` set produces `detail.sources.windows_update == true` with the other two `false`.
2. The alert detail page for that alert states the restart is update-related and lists KBs installed in the lookback window, labeled as correlated evidence.
3. An endpoint with only `PendingFileRenameOperations` set shows a pending restart that is **not** attributed to updates.
4. An alert from an agent that predates this change renders "Cause unavailable", and no test asserts a cause for it.
5. The alerts list response is unchanged; a `cpu` alert's detail has `reboot_cause == null`.
6. `go test ./...`, `pytest -q`, and the full dashboard command set pass.

## Resolved Decisions

1. **Agent rollout: layer 2 first, layer 1 second.** Two releases, not one.
   Layer 2 is server-only, so it reaches every endpoint the moment the server
   deploys, with no agent rollout to wait on and nothing to coordinate. Layer 1
   then upgrades the same UI from correlated evidence to a categorical answer.
   Shipping together would hold a fleet-wide improvement hostage to an agent
   release for no gain — and would leave the cause-unavailable path, which
   pre-update agents hit forever, unexercised until it was already in production.

2. **`PendingFileRenameOperations`: count only, paths never leave the endpoint.**
   The paths routinely contain user names (`C:\Users\jsmith`) and sometimes
   installer temp paths that disclose internal software. They would flow into
   `CheckResult.detail`, which fans out over alert email and third-party
   webhooks — so a path here leaves the tenant boundary. Against that, the paths
   add almost no triage value: knowing a file-rename reboot is pending is the
   actionable fact, and the file list does not change what the technician does.
   `redaction.py` is pattern-based (`_redact_scalar_str`, `is_sensitive_key`) and
   would not reliably strip a user name from an arbitrary path, so leaning on it
   here would be a false guarantee. Report `pending_file_rename_count` and stop.

3. **Lookback window: fixed constant, 7 days.** Named
   `REBOOT_CAUSE_LOOKBACK = timedelta(days=7)` in `app/core/monitoring.py`.
   Not per-policy and not a setting: it tunes a correlation heuristic, and an
   operator has no basis on which to pick a better number. If real use shows
   7 days is wrong, changing a constant is a one-line change; withdrawing a
   configuration surface operators have already set is not.
