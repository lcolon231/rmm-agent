# Patch approval policies and maintenance windows

Issue #52 adds a server-side control plane over Windows Update installation
(#51): scoped approval/deny/defer rules, an auditable effective policy, and
recurring timezone/DST-aware maintenance windows. It changes no agent or command
envelope — the gate runs before a command is signed and only ever narrows or
blocks an `install_updates` payload the agent already understands.

## Policy model

A **patch approval policy** is a stable identity (`name`, `scope`, `scope_id`,
`enabled`) whose rule content lives in append-only revisions, mirroring
monitoring policies. Scopes are `global`, `client`, `site`, `agent`.

A revision holds:

- `rules`: an **ordered, first-match** list. Each rule is
  `{key, action, match, defer_days?}` where `action` is `approve`, `deny`, or
  `defer`, and `match` constrains at least one of `classifications`,
  `severities`, or `kb_ids`. Facets within a rule are ANDed; use separate rules
  for OR. A KB-specific rule placed before broader rules expresses an exception.
- `default_action` (`approve` or `deny`, default `deny`): applied to an update no
  rule matches.
- `require_maintenance_window` (bool): gates install dispatch on an active
  maintenance window.

`defer` approves an update only once it is old enough:
`now - last_deployment_change >= defer_days`. If the update's release date is
unknown it stays deferred — fail closed.

## Effective policy

The single **most-specific enabled policy** that targets an endpoint governs it
(`agent` > `site` > `client` > `global`; earliest-created wins within a scope).
Unlike monitoring's per-check merge, patch rules are ordered and first-match, so
a more-specific policy overrides a less-specific one wholesale. `GET
/agents/{id}/patch-approval/effective` returns the resolved policy plus the
decision for each currently-missing update.

## Enforcement

On an `install_updates` dispatch the server:

1. Resolves the effective policy. **With no policy, the payload is unchanged**
   (opt-in) — existing installs are unaffected until a policy is authored.
2. If `require_maintenance_window`, requires an active window
   (`patch_install_maintenance_window_required`).
3. Evaluates the targeted updates against the agent's latest scanned inventory:
   - **`install_all`** is narrowed to the approved subset and re-dispatched as an
     explicit KB/update-id list; an empty approved set is refused
     (`patch_install_no_approved_updates`).
   - An **explicit selection** is fail-closed: any denied, deferred, or
     not-currently-scanned target refuses the whole command
     (`patch_install_denied`, with the blocked identifiers).
4. Records one `patch_install.gated` audit event with the outcome and the
   approved/denied/deferred counts — never update titles.

Authorization is unchanged: `install_updates` remains an operator-role typed
operation. Policy CRUD requires the operator role; reads require readonly.

## Maintenance windows: recurrence and DST

Maintenance windows gain an optional IANA `timezone` and a weekly `recurrence`
`{days: [0-6], start: "HH:MM", duration_minutes}`. An absolute window (no
recurrence) is unchanged. A recurring window is active when "now", converted to
its timezone via `zoneinfo`, falls inside a weekly occurrence; both the current
and previous local day are checked so an occurrence spanning midnight or a DST
transition still matches. `tzdata` is a server dependency so IANA zones resolve
on Windows and slim Linux images. Power operations consume the same
`active_maintenance_windows` seam and benefit automatically.

## States and failure behavior

- Policy create/revise/delete: `201`/`200`/`204`; duplicate name in a scope →
  `409 patch_approval_policy_name_exists`; unknown scope target → `404`; invalid
  scope/rule/timezone → `422`.
- Install gate refusals are all `409` with the codes above; each is preceded by a
  durable `patch_install.gated` audit record.

## Audit

`patch_approval_policy.created` / `.revised` / `.deleted` (names and change notes
are digest-only) and `patch_install.gated` (counts and outcome only). See
[`AUDIT-EVENTS.md`](AUDIT-EVENTS.md).

## Rollout

Server-only, forward-only. Deploy migration `0033` and the server, then the
dashboard. `0033` creates the two `patch_approval_policies*` tables and adds
nullable `timezone`/`recurrence` to `maintenance_windows`; existing absolute
windows and existing installs are unaffected. Policies are opt-in, so nothing
changes until one is authored.

## Verification

- Server: `server/tests/test_patch_policies.py` covers CRUD, scope validation,
  most-specific resolution, deny/narrow/defer evaluation (including defer age and
  unknown-release fail-closed), the maintenance-window requirement with a
  recurring window, and opt-in passthrough; `server/tests/test_power_operations.py`
  confirms the window change does not regress power ops.
- Dashboard: `dashboard/test/patch-policies-core.test.ts` covers allowlisted,
  fail-closed parsing and formatters.
