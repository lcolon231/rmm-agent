# Spec: patch-age-windows

Module id: `patch-age-windows` (see `specs/CAPABILITY-MAP-patch-alerting.md`)

## Objective

Alert an operator when an endpoint has not installed a Windows Update in a
configurable amount of time, so a machine that has silently stopped taking
patches is visible before it becomes an incident.

**User story.** As a technician, I configure a monitoring policy with a
`patch_age` check at warning 30 days / critical 60 days. Any endpoint whose most
recent installed update is older than that opens an alert on the alerts page,
with the same acknowledge/assign/resolve lifecycle, maintenance-window
suppression, and email/webhook fan-out as every other check.

**Explicitly not this feature.** "The update *scan* is stale" is a different
signal and already exists as `patch_compliance` state `stale`
(`server/app/core/patch_compliance.py`). This check measures install recency,
not scan recency. An endpoint can be freshly scanned and badly out of date, or
well patched and unscanned; both must remain distinguishable.

## Tech Stack

- Server: Python 3, FastAPI, SQLAlchemy 2 (async), Pydantic v2, Alembic
- Dashboard: Next.js 16.2.12, React 19.2.4, TypeScript 5, Node >= 24
- Tests: `pytest` + `pytest-asyncio` (asyncio_mode=auto); `node --test` for the dashboard

## Commands

```
# Server
cd server
pip install -r requirements.txt pytest pytest-asyncio httpx aiosqlite "moto[s3]"
python scripts/gen_command_keys.py     # once, before the first test run
pytest -q
pytest -q tests/test_patch_age_checks.py

# Dashboard
cd dashboard
npm ci
npm run lint
npm run typecheck
npm test
npm run build
```

## Project Structure

Files this module touches:

```
server/app/models/models.py              -> add CheckType.patch_age
server/app/schemas/monitoring.py         -> CHECK_PARAM_MODELS entry, threshold validation
server/app/core/monitoring.py            -> evaluate_patch_age_checks()
server/app/core/tasks.py                 -> call it from _sweep_once()
server/tests/test_patch_age_checks.py    -> new
dashboard/src/lib/monitoring-core.ts     -> CheckType union + checkTypes set
dashboard/test/monitoring-core.test.ts   -> extend
docs/MONITORING.md                       -> supported-checks table row
```

**No Alembic migration.** `MonitoringPolicyRevision.checks` is a JSON column
whose docstring states outright that "adding a new check type is a schema
change, not a migration" (`server/app/models/models.py:1208`), and `CheckResult`
stores `check_key`, not a check type. `CheckType` appears in no `Enum()` column.

## Design

### Server-evaluated, like `offline`

`patch_age` is evaluated by the server from stored inventory, not probed by the
agent. `WindowsUpdatesInventory.installed[].installed_on`
(`server/app/schemas/inventory.py:479`) is already on the server; a new agent
probe would duplicate it and require an agent release.

`evaluate_patch_age_checks(db, agent, at)` mirrors `evaluate_offline_checks`
(`server/app/core/monitoring.py:680`) exactly — same effective-policy
resolution, same "previous result from a different revision resets transition
state" rule, same `interval_seconds` due-check, same `_apply_hysteresis`, same
`record_check_result` write — and is called from `tasks._sweep_once` beside it.

### Value and threshold

- **Value**: age in **days** (float) of the newest non-null `installed_on`
  across `installed[]` in the latest `windows_updates` snapshot, clamped at 0.
- **Threshold**: rising, so `op` must be `gt` or `gte`. `classify_numeric`
  already evaluates critical before warning, and `Threshold` already enforces
  `critical >= warning` for a rising op (`server/app/schemas/monitoring.py:100`).
- **Params**: none (`_NoParams`), like `cpu` and `reboot_pending`.
- **Cadence floor**: `interval_seconds` must be `>= 3600` for `patch_age`,
  enforced in `CheckDefinition` validation. The global floor stays
  `MIN_CHECK_INTERVAL_SECONDS = 30` for every other type.
- Reject `lt`/`lte` at policy-submit time with a clear error: a falling
  patch-age threshold is always an operator mistake, and accepting it would
  silently invert the alert.

Days rather than seconds because the operator-facing unit is days, and a float
carries sub-day precision without introducing a second unit concept.

The cadence floor exists because `_sweep_once` runs every
`heartbeat_interval_seconds` (default 60). A quantity that moves on a scale of
days has nothing to gain from minute-resolution evaluation, and each evaluation
costs an inventory read per agent. The floor is only meaningful if the due-check
short-circuits *before* that read — the loop must load the previous result,
compare `evaluated_at`, and `continue` while not due, exactly as
`evaluate_offline_checks` does.

### `unknown`, never `ok`

`unknown` is returned — with the reason recorded in `detail` — when:

| Condition | `detail.reason` |
|---|---|
| No `windows_updates` snapshot for the agent | `no_update_inventory` |
| Snapshot `status` not in `{ok, partial}` | `update_scan_unusable` |
| `installed[]` empty | `no_installed_updates` |
| Every `installed_on` is null | `no_install_timestamps` |
| Newest `installed_on` is in the future beyond clock skew | `install_timestamp_in_future` |

"Never scanned" must not read as "well patched". The existing contract is that
`unknown` is never treated as `ok` (`docs/MONITORING.md`), and this check leans
on it. A non-Windows endpoint therefore reads `unknown`, which is correct and
leaves room for a second evidence source later without a new check type.

### Result detail payload

```json
{
  "check_type": "patch_age",
  "reason": "newest_install_within_threshold",
  "raw_status": "ok",
  "evidence_source": "windows_updates",
  "newest_installed_on": "2026-08-14T03:11:00Z",
  "newest_kb_id": "KB5041585",
  "installed_count": 214,
  "scanned_at": "2026-09-01T22:04:00Z",
  "snapshot_received_at": "2026-09-01T22:06:11Z",
  "hysteresis": {"pending_status": null, "pending_count": 0}
}
```

`evidence_source` is present from day one so a later source is a value change,
not a payload shape change. `scanned_at` and `snapshot_received_at` are included
because an operator triaging a patch-age alert immediately needs to know how old
the evidence itself is. Detail is bounded JSON, validated at
`server/app/schemas/monitoring.py:319`.

### Clock skew

`installed_on` comes from the endpoint's clock. Treat a future timestamp within
`INSTALL_TIMESTAMP_SKEW_TOLERANCE` (5 minutes) as age 0; beyond that, report
`unknown` with `install_timestamp_in_future` rather than a negative age.

## Code Style

Match `evaluate_offline_checks` — the new evaluator is a deliberate structural
twin, and reviewers should be able to diff them:

```python
async def evaluate_patch_age_checks(
    db: AsyncSession, agent: Agent, at: datetime | None = None
) -> int:
    """Evaluate due server-owned patch-age checks for one endpoint."""
    at = at or _now()
    written = 0
    for assignment in await resolve_effective_policy(db, agent):
        definition = assignment.definition
        if definition.type is not CheckType.patch_age:
            continue
        previous = await _previous_result(db, agent.id, definition.key)
        if previous is not None and (
            previous.policy_id != assignment.source_policy_id
            or previous.policy_revision_id != assignment.source_revision_id
        ):
            # A new revision may change thresholds, cadence, or hysteresis.
            # Never carry transition state or its due time across that boundary.
            previous = None
        ...
```

Conventions the module follows: `from __future__ import annotations`; SPDX
header on every new file; timezone-aware UTC datetimes normalized through the
existing `.replace(tzinfo=... or timezone.utc)` idiom; comments explain *why* a
rule exists, not what the line does.

## Testing Strategy

`pytest` with `asyncio_mode=auto`, against SQLite via `aiosqlite`, following the
existing `server/tests/` patterns. New file `server/tests/test_patch_age_checks.py`.

| Level | Cases |
|---|---|
| Schema | `patch_age` accepted with a rising threshold and no params; `lt`/`lte` rejected; unknown params rejected |
| Evaluator | ok below threshold; warning and critical at each bound; each of the five `unknown` reasons; newest-of-many `installed_on` wins; null `installed_on` entries skipped, not treated as age 0 |
| Cadence | not re-evaluated before `interval_seconds`; re-evaluated after; a sweep on a not-due check performs no inventory read |
| Cadence floor | `interval_seconds` below 3600 rejected for `patch_age`; 30 still accepted for `cpu` |
| Revision boundary | transition state reset when the policy revision changes |
| Hysteresis | `raise_samples`/`clear_samples` debounce a flapping threshold |
| Lifecycle | crossing to critical opens an `Alert`; dropping to ok resolves it with `automatic_recovery` |
| Skew | 2-minute-future timestamp is age 0; 2-hour-future is `unknown` |

Dashboard: extend `dashboard/test/monitoring-core.test.ts` to assert `patch_age`
parses as a valid `CheckType` and that an unknown type is still rejected.

Coverage expectation: every branch of `evaluate_patch_age_checks` exercised.
Note that `npm test` lists its test files explicitly in `package.json`, so a new
dashboard test file must be added to that list or it silently never runs.

## Boundaries

**Always**
- Run `pytest -q` (server) and `npm run lint && npm run typecheck && npm test` (dashboard) before committing
- Return `unknown` with a specific reason rather than guessing an age
- Keep `evaluate_patch_age_checks` structurally parallel to `evaluate_offline_checks`
- Update `docs/MONITORING.md`'s supported-checks table in the same change

**Ask first**
- Adding an Alembic migration (this module is designed to need none — if one seems necessary, the design has drifted)
- Adding a new inventory section or changing `WindowsUpdatesInventory`
- Changing `classify_numeric`, `_apply_hysteresis`, or anything else shared with the shipped checks
- Seeding a default monitoring policy (explicitly declined; the check stays opt-in)

**Never**
- Report `ok` for an endpoint with no usable update evidence
- Make the check agent-probed, or add a new typed command for it
- Conflate patch age with `patch_compliance`'s `stale` scan state
- Widen the retention or pruning behavior of `check_results`

## Success Criteria

1. A policy with `{"type": "patch_age", "threshold": {"op": "gt", "warning": 30, "critical": 60}}` is accepted; the same check with `"op": "lt"` is rejected with a validation error.
2. An agent whose newest `installed_on` is 75 days old produces a `critical` `CheckResult` and an open `Alert` within one sweep interval.
3. That alert resolves automatically with `automatic_recovery` after inventory reports an update installed today.
4. An agent with no `windows_updates` snapshot produces `unknown` with `reason == "no_update_inventory"` and **no** alert.
5. The alert honors an active maintenance window and fans out to email/webhook exactly like a `cpu` alert — no new notification code paths.
6. `pytest -q` and the full dashboard command set pass; `docs/MONITORING.md` lists `patch_age`.

## Resolved Decisions

1. **Cadence floor: yes, 3600 seconds, schema-enforced.** Cheap insurance
   against an operator setting a 30-second patch-age check and paying an
   inventory read per agent per sweep for a value that changes on a scale of
   days. Type-specific rather than global so the existing floor of 30 for every
   other check is untouched.
2. **Threshold defaults: none.** `patch_age` stays fully operator-specified like
   every other check type. A schema-supplied 30/60 would be the only check with
   a built-in opinion, and a prefilled threshold reads as a recommendation the
   product cannot actually justify across every customer's patch cadence.
