# Tasks: Patch-State Alerting

Plan: `tasks/plan.md`. Specs: `specs/SPEC-patch-age-windows.md`, `specs/SPEC-reboot-cause.md`.

Standing bar for every task is the Definition of Done in `tasks/plan.md`.

---

# Release A — `patch-age-windows` (#229)

## Task A1: Add the `patch_age` check type and its validation

**Description:** Register `patch_age` as a check type with no params, a
rising-only threshold, and a 3600-second minimum evaluation interval. Policy
submission is the only gate that can reject a nonsensical patch-age check, so
all three rules live here.

**Acceptance criteria:**
- [ ] `CheckType.patch_age` exists; `CHECK_PARAM_MODELS[CheckType.patch_age]` is `_NoParams`
- [ ] A check with `op` of `lt`/`lte` is rejected with a clear error; `gt`/`gte` accepted
- [ ] `interval_seconds < 3600` rejected for `patch_age` only — `cpu` still accepts 30

**Verification:**
- [ ] `cd server && pytest -q tests/test_patch_age_checks.py`
- [ ] `cd server && pytest -q` (no existing monitoring test regresses)

**Dependencies:** None

**Files likely touched:**
- `server/app/models/models.py`
- `server/app/schemas/monitoring.py`
- `server/tests/test_patch_age_checks.py`

**Estimated scope:** S

---

## Task A2: Implement `evaluate_patch_age_checks`

**Description:** Derive patch age in days from the newest non-null
`installed_on` in the latest `windows_updates` snapshot, and record a result
through the existing storage seam. A deliberate structural twin of
`evaluate_offline_checks` — same revision-boundary reset, same due-check, same
hysteresis, same `record_check_result`.

**Acceptance criteria:**
- [ ] Age in days classifies ok/warning/critical against the policy threshold; newest of many `installed_on` wins and null entries are skipped, not treated as age 0
- [ ] All five `unknown` reasons emitted per the spec's table; `unknown` is never `ok`
- [ ] A future `installed_on` within 5 minutes is age 0; beyond that is `unknown` with `install_timestamp_in_future`
- [ ] A not-due check performs **no** inventory read (the due-check short-circuits first)

**Verification:**
- [ ] `cd server && pytest -q tests/test_patch_age_checks.py`
- [ ] Manual check: the new function reads as a diff of `evaluate_offline_checks` (`server/app/core/monitoring.py:680`)

**Dependencies:** A1

**Files likely touched:**
- `server/app/core/monitoring.py`
- `server/tests/test_patch_age_checks.py`

**Estimated scope:** M

---

## Task A3: Evaluate patch-age checks in the background sweep

**Description:** Call the evaluator from `_sweep_once` beside the offline
evaluation, with its own metric counter.

**Acceptance criteria:**
- [ ] `_sweep_once` evaluates patch-age checks for every active-trust agent
- [ ] A `monitoring_patch_age_evaluation_total` counter reports results written
- [ ] A sweep raises no error for an agent with no inventory at all

**Verification:**
- [ ] `cd server && pytest -q tests/test_patch_age_checks.py tests/test_monitoring*.py`

**Dependencies:** A2

**Files likely touched:**
- `server/app/core/tasks.py`
- `server/tests/test_patch_age_checks.py`

**Estimated scope:** S

---

### Checkpoint: Release A server path (after A1–A3)

- [ ] `cd server && pytest -q` passes
- [ ] End-to-end: a policy with `patch_age` warning 30 / critical 60 against an agent whose newest install is 75 days old opens a `critical` `Alert`
- [ ] Inventory reporting an install today auto-resolves that alert with `automatic_recovery`
- [ ] An agent with no `windows_updates` snapshot yields `unknown` / `no_update_inventory` and **no** alert
- [ ] **Verify against an endpoint with a real `scan_updates` result**, not only fixtures — this is where the plan's highest risk shows up
- [ ] Review with human before proceeding

---

## Task A4: Accept `patch_age` in the dashboard check-type contract

**Description:** Add the type to the union and runtime-validated set so policies
containing it parse instead of being rejected.

**Acceptance criteria:**
- [ ] `CheckType` union and the `checkTypes` set both include `patch_age`
- [ ] A policy payload with `patch_age` parses; an unknown type is still rejected
- [ ] `formatCheckType` renders it as "patch age" (no code change expected — assert it)

**Verification:**
- [ ] `cd dashboard && npm run lint && npm run typecheck && npm test`

**Dependencies:** A1. Read `dashboard/node_modules/next/dist/docs/` before writing dashboard code (see `dashboard/AGENTS.md`).

**Files likely touched:**
- `dashboard/src/lib/monitoring-core.ts`
- `dashboard/test/monitoring-core.test.ts`

**Estimated scope:** XS

---

## Task A5: Document the `patch_age` check

**Description:** Add the supported-checks row and — critically — state that
`patch_age` needs a recurring `scan_updates` schedule to be meaningful, since
`windows_updates` inventory is on-demand.

**Acceptance criteria:**
- [ ] Supported-checks table lists `patch_age` with its input, passing state, and unavailable behavior
- [ ] The `scan_updates` scheduling prerequisite is stated explicitly
- [ ] `patch_age` is distinguished in prose from `patch_compliance`'s `stale` scan state

**Verification:**
- [ ] Manual check: `docs/MONITORING.md` renders and the table row matches the shipped reasons

**Dependencies:** A3

**Files likely touched:**
- `docs/MONITORING.md`

**Estimated scope:** XS

---

### Checkpoint: Release A complete

- [ ] Every success criterion in `specs/SPEC-patch-age-windows.md` is met
- [ ] Server, dashboard, and agent command sets all pass
- [ ] Ready for review

---

# Release B — `reboot-cause` layer 2 (#230) — server-derived, no agent release

## Task B1: Derive reboot cause from update inventory

**Description:** Add `REBOOT_CAUSE_LOOKBACK = timedelta(days=7)` and a
`derive_reboot_cause` function correlating a pending reboot with recent update
activity. Correlational only — naming and docstrings must say so. Implements the
absent-`sources` rule now, because in this release *every* alert takes that path.

**Acceptance criteria:**
- [ ] Returns flagged missing updates, recent installs inside the lookback (newest first, max 10), `system_reboot_required`, `scanned_at`, `snapshot_received_at`
- [ ] Installs outside the lookback window are excluded; more than 10 truncates newest-first
- [ ] Absent `sources` in the result detail yields unknown-cause — **never** "no update-related cause"
- [ ] Returns `None` when there is no snapshot and nothing to say

**Verification:**
- [ ] `cd server && pytest -q tests/test_reboot_cause.py`

**Dependencies:** None

**Files likely touched:**
- `server/app/core/monitoring.py`
- `server/tests/test_reboot_cause.py`

**Estimated scope:** M

---

## Task B2: Expose result detail and cause on `AlertDetailOut`

**Description:** Add `last_result_detail` and `reboot_cause` to the single-alert
response schema. `CheckResult.detail` has no API surface today, so this defines
the contract that B4, B5, and C3 all depend on.

**Acceptance criteria:**
- [ ] `RebootCauseOut` models the B1 payload; both new fields default to `None`
- [ ] `AlertOut` and `AlertListOut` are unchanged
- [ ] Payload field names carry the correlational framing (no field named as if it were causal)

**Verification:**
- [ ] `cd server && pytest -q`

**Dependencies:** B1

**Files likely touched:**
- `server/app/schemas/monitoring.py`
- `server/tests/test_reboot_cause.py`

**Estimated scope:** S

---

## Task B3: Populate cause on the alert-detail route

**Description:** For a `reboot_pending` alert, load its `CheckResult` by
`last_result_id`, resolve the check type from the stored policy revision, load
the latest `windows_updates` snapshot, and attach the derived cause.

**Acceptance criteria:**
- [ ] A reboot alert's detail response carries `last_result_detail` and `reboot_cause`; a `cpu` alert's carries `None` for both
- [ ] An alert whose `policy_revision_id` no longer exists returns `reboot_cause: null` and **does not 500** (`Alert.policy_revision_id` is intentionally not a foreign key)
- [ ] The alerts *list* response is byte-identical to before this change
- [ ] No update scan is triggered from this read path

**Verification:**
- [ ] `cd server && pytest -q tests/test_reboot_cause.py`
- [ ] `cd server && pytest -q` (alert route tests unaffected)

**Dependencies:** B2

**Files likely touched:**
- `server/app/api/management.py`
- `server/tests/test_reboot_cause.py`

**Estimated scope:** M

---

### Checkpoint: Release B server path (after B1–B3)

- [ ] `cd server && pytest -q` passes
- [ ] A live reboot alert returns correlated update evidence and an unknown cause
- [ ] Alerts list latency is unchanged (no per-row inventory read)
- [ ] Review with human before proceeding

---

## Task B4: Parse the cause payload in the dashboard

**Description:** Add the types and runtime validation for the two new
`AlertDetailOut` fields.

**Acceptance criteria:**
- [ ] Types for `last_result_detail` and `reboot_cause` match the B2 schema
- [ ] A malformed or absent cause payload parses to `null` rather than throwing
- [ ] Existing alert parsing is unchanged

**Verification:**
- [ ] `cd dashboard && npm run lint && npm run typecheck && npm test`

**Dependencies:** B2. Read `dashboard/node_modules/next/dist/docs/` first.

**Files likely touched:**
- `dashboard/src/lib/monitoring-core.ts`
- `dashboard/test/monitoring-core.test.ts`

**Estimated scope:** S

---

## Task B5: Render the cause panel on the alert detail page

**Description:** Add a panel beside the existing evidence panel showing the
correlated update evidence, worded as correlation. It must render all three
states, and in this release the unavailable state is what every alert shows.

**Acceptance criteria:**
- [ ] Renders: cause unavailable (with correlated list beneath), update-correlated, and no-evidence
- [ ] Copy never asserts causation — an operator reading it cannot conclude "this update caused it" as fact
- [ ] Panel is absent, not empty, for a non-reboot alert

**Verification:**
- [ ] `cd dashboard && npm run lint && npm run typecheck && npm test && npm run build`
- [ ] Manual check: open a reboot alert and a `cpu` alert; confirm the panel appears only on the former

**Dependencies:** B4

**Files likely touched:**
- `dashboard/src/app/alerts/[alertId]/page.tsx`
- `dashboard/src/app/globals.css`

**Estimated scope:** M

---

## Task B6: Document the reboot cause payload

**Acceptance criteria:**
- [ ] `docs/ALERTS.md` documents the cause block and its correlational meaning
- [ ] The mixed-agent-version rule is stated: absent sources means unknown, not "not update-related"

**Verification:**
- [ ] Manual check: docs match the shipped payload field-for-field

**Dependencies:** B5

**Files likely touched:**
- `docs/ALERTS.md`
- `docs/MONITORING.md`

**Estimated scope:** XS

---

### Checkpoint: Release B complete

- [ ] Success criteria 4, 5, and 6 of `specs/SPEC-reboot-cause.md` are met
- [ ] Ready to ship independently of Release C
- [ ] Review with human before proceeding

---

# Release C — `reboot-cause` layer 1 (#231) — needs an agent release

## Task C1: Report which reboot sources are set

**Description:** Change the Windows probe from a single boolean to per-source
flags plus a best-effort `PendingFileRenameOperations` entry count. Paths are
never returned.

**Acceptance criteria:**
- [x] Each of the three registry sources alone sets exactly its own flag; all three set works
- [x] Probe failure still yields unavailable with `reboot_probe_failed` — a count query error never changes status
- [x] The count is a count; **no file paths are returned from the probe under any code path**
- [x] `probe_other.go` stub compiles and reports unsupported

**Verification:**
- [x] `cd agent && go vet ./... && go build ./... && go test ./...`
- [x] Manual check: grep the diff for any path-valued return

**Dependencies:** None (but ship after Release B)

**Files likely touched:**
- `agent/internal/monitoring/probe.go`
- `agent/internal/monitoring/probe_windows.go`
- `agent/internal/monitoring/probe_other.go`
- `agent/internal/monitoring/probe_windows_test.go`

**Estimated scope:** M

---

## Task C2: Carry sources into the check result detail

**Description:** Include `sources` and `pending_file_rename_count` in the
`reboot_pending` result detail. Status logic must not move.

**Acceptance criteria:**
- [x] Detail carries the three source booleans and the count
- [x] **Regression guard:** ok/critical/unknown outcomes are identical to before for every existing evaluator test case
- [x] Detail stays within the bounded-JSON limit enforced server-side

**Verification:**
- [x] `cd agent && go test ./...`

**Dependencies:** C1

**Files likely touched:**
- `agent/internal/monitoring/evaluator.go`
- `agent/internal/monitoring/evaluator_test.go`

**Estimated scope:** S

---

## Task C3: Give a categorical cause when sources are present

**Description:** Extend `derive_reboot_cause` to state the cause categorically
when `sources` is present, keeping the unknown path for agents that predate C2.

**Acceptance criteria:**
- [x] `windows_update` true yields an update-caused verdict; only `pending_file_rename` true yields not-update-caused
- [x] Detail with no `sources` key still yields unknown-cause (mixed-version test, kept from B1)
- [x] Correlated evidence from layer 2 is still returned alongside the verdict

**Verification:**
- [x] `cd server && pytest -q tests/test_reboot_cause.py`
- [x] `cd server && pytest -q`

**Dependencies:** C2, B3

**Files likely touched:**
- `server/app/core/monitoring.py`
- `server/app/schemas/monitoring.py`
- `server/tests/test_reboot_cause.py`

**Estimated scope:** S

---

## Task C4: Render the categorical verdict

**Acceptance criteria:**
- [x] Update-caused and not-update-caused states render distinctly from unknown
- [x] The correlated list remains visible and still labeled as correlation
- [x] A pre-C2 agent's alert still renders "cause unavailable"

**Verification:**
- [x] `cd dashboard && npm run lint && npm run typecheck && npm test && npm run build`

**Dependencies:** C3. Read `dashboard/node_modules/next/dist/docs/` first.

**Files likely touched:**
- `dashboard/src/lib/monitoring-core.ts`
- `dashboard/src/app/alerts/[alertId]/page.tsx`
- `dashboard/test/monitoring-core.test.ts`

**Estimated scope:** S

---

## Task C5: Document the source flags and the agent version requirement

**Acceptance criteria:**
- [x] `docs/MONITORING.md` documents the `sources` payload
- [ ] Release notes state which agent version is required for categorical cause reporting
      (deferred to the release cut: `release-notes/<tag>.json` is written from
      TEMPLATE.json with immutable digests and a verified backup, per
      `docs/RELEASING.md`, so it cannot be authored ahead of the tag. The
      requirement itself — agent v0.1.8+ — is documented in `docs/MONITORING.md`
      and `docs/ALERTS.md`, and must be restated in the v0.1.8 manifest.)
- [x] Documented that `PendingFileRenameOperations` paths are deliberately never collected

**Verification:**
- [x] Manual check: docs match the shipped payload

**Dependencies:** C4

**Files likely touched:**
- `docs/MONITORING.md`
- `release-notes/`

**Estimated scope:** XS

---

### Checkpoint: Release C complete

- [x] Every success criterion in `specs/SPEC-reboot-cause.md` is met
- [x] Agent, server, and dashboard command sets all pass
      (`tests/test_anchor_publish.py` was skipped locally: `boto3` is not installed)
- [x] Ready for review
