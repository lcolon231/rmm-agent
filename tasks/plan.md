# Implementation Plan: Patch-State Alerting

Specs: `specs/CAPABILITY-MAP-patch-alerting.md`, `specs/SPEC-patch-age-windows.md`,
`specs/SPEC-reboot-cause.md`. Tasks: `tasks/todo.md`.

## Overview

Two operator-facing alerts, delivered as three independently shippable releases:

| Release | Issue | Module | Ships | Needs an agent release |
|---|---|---|---|---|
| **A** | #229 | `patch-age-windows` | New `patch_age` check: endpoint has not installed an update in N days | No |
| **B** | #230 | `reboot-cause` layer 2 | Restart alerts carry correlated update evidence | No |
| **C** | #231 | `reboot-cause` layer 1 | Restart alerts state the cause categorically | Yes |

A and B are independent and may be built in either order or in parallel by two
sessions — they share no files. C depends on B.

## Architecture Decisions

Carried from the approved specs; recorded here so implementation does not
relitigate them.

- **`patch_age` is server-evaluated from stored inventory**, structurally
  mirroring `evaluate_offline_checks`. The data (`installed[].installed_on`) is
  already on the server; an agent probe would duplicate it and gate the feature
  on a fleet rollout.
- **No Alembic migration anywhere in this plan.** `MonitoringPolicyRevision.checks`
  is JSON and its docstring states a new check type is a schema change, not a
  migration; `CheckResult` stores `check_key`, not a type. If a task appears to
  need a migration, the design has drifted — stop and re-read the spec.
- **`unknown` never reads as `ok`.** An endpoint with no usable update evidence
  reports `unknown` with a specific reason. This is what keeps "never scanned"
  from rendering as "well patched", and it is what leaves room for a
  non-Windows evidence source later without a new check type.
- **Cause lands on `AlertDetailOut` only, never the list.** Joining inventory
  per row would turn the alerts list into an N+1 inventory scan.
- **A missing `sources` key means unknown cause, never "not update-related".**
  Release B ships before any agent reports sources, so this is the *default*
  render path in B, not an edge case.
- **`PendingFileRenameOperations`: count only, paths never leave the endpoint.**
  `CheckResult.detail` fans out over email and third-party webhooks.

## Dependency Graph

```
Release A (patch-age-windows)            Release B (reboot-cause L2)
  A1 schema: CheckType.patch_age           B1 derive_reboot_cause + lookback
      │                                        │
  A2 evaluate_patch_age_checks               B2 AlertDetailOut fields
      │                                        │
  A3 wire into _sweep_once                   B3 alert-detail route wiring
      │                                        │
  ══ CHECKPOINT A ══                        ══ CHECKPOINT B ══
      │                                        │
  A4 dashboard CheckType                     B4 dashboard parse
      │                                        │
  A5 docs                                    B5 alert detail cause panel
                                               │
                                             B6 docs
                                               │
                                          Release C (reboot-cause L1)
                                             C1 Go probe -> RebootSources
                                               │
                                             C2 evaluator carries sources
                                               │
                                             C3 server consumes sources
                                               │
                                             C4 dashboard categorical state
                                               │
                                             C5 docs + agent release notes
```

Bottom-up within each release: schema/derivation → server wiring → checkpoint →
dashboard → docs. Each release ends in a shippable state.

## Vertical Slices

Each release is one complete user-visible path, not a horizontal layer:

- **A** — "I set a 30/60-day patch-age policy and a stale endpoint alerts me."
- **B** — "I open a restart alert and see which updates were installed recently."
- **C** — "The same alert tells me categorically whether an update caused it."

## Parallelization

- **Safe in parallel:** Release A and Release B (disjoint files; A touches
  `core/monitoring.py` only by adding a new function, B only by adding another —
  coordinate if both land in the same session to avoid a merge conflict in that
  one file).
- **Must be sequential:** C after B (C3 extends the function B1 creates).
- **Needs coordination:** B2 defines the `reboot_cause` payload shape consumed
  by B4/B5 and extended by C3. Land B2 before starting B4.

## Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| **Most endpoints have no `windows_updates` snapshot**, so `patch_age` reads `unknown` fleet-wide and the feature looks broken on day one. The section is populated only by the on-demand `scan_updates` command, not the heartbeat path. | **High** | Not a code change: `ScheduledTask.kind` is a `CommandKind`, so `scan_updates` can be scheduled recurringly today. Document it in `docs/MONITORING.md` as a prerequisite for `patch_age`, and verify at Checkpoint A against an endpoint with a real scan. |
| The alert-detail route must resolve a `check_key` to a check *type*, but `Alert.policy_revision_id` is deliberately **not** a foreign key — the revision may have been deleted. | Medium | `reboot_cause` is `None` when the revision is gone. Task B3 has an explicit test for a deleted-revision alert; it must not 500. |
| Counting `PendingFileRenameOperations` entries changes a PowerShell probe that currently only tests presence — a script error would turn a working check `unknown`. | Medium | Keep the existing presence test as the authority for status. The count is best-effort: on any parse or query error, report `0`/absent and leave status untouched. C1 tests the probe-failure path explicitly. |
| Dashboard work assumes familiar Next.js. `dashboard/AGENTS.md` states this version has breaking changes versus training data. | Medium | Before writing any dashboard code (A4, B4, B5, C4), read the relevant guide under `dashboard/node_modules/next/dist/docs/`. |
| A new dashboard test file silently never runs — `npm test` lists files explicitly in `package.json`. | Low | No new dashboard test files in this plan; all extend existing ones. If one is added, update the `test` script in the same commit. |
| `patch_age` evaluation adds an inventory read per agent per sweep. | Low | 3600s schema floor on `interval_seconds`, plus a test asserting a not-due check performs no inventory read. |

## Definition of Done (standing bar for every task)

Beyond each task's own acceptance criteria:

- `cd server && pytest -q` passes
- `cd agent && go vet ./... && go build ./... && go test ./...` passes (tasks touching Go)
- `cd dashboard && npm run lint && npm run typecheck && npm test && npm run build` passes (tasks touching the dashboard)
- SPDX header on every new file
- No secrets, endpoint paths, or user names added to any payload
- The spec is updated first if the task changes a documented decision

## Open Questions

None blocking. All three spec-level questions were resolved before planning; see
the Resolved Decisions section of each spec.
