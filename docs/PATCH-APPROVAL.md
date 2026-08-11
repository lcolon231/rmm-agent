# Patch approval, installation, and reboot policies

Issue #52 adds a server-side control plane over Windows Update installation
(#51): scoped approval/deny/defer rules, an auditable effective policy, and
recurring timezone/DST-aware maintenance windows. The gate runs before a command
is signed and only ever narrows or blocks an `install_updates` payload. Issue #53
adds per-update result tracking, bounded retry, and a post-install reboot policy,
and routes scheduled installs through the same gate — see
"Installation and reboot (issue #53)" below.

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

## Installation and reboot (issue #53)

A policy revision also carries installation and reboot behavior:

- **`reboot_policy`** — `never` (default, fail-safe), `if_required`, or `forced`.
  **`reboot_delay_seconds`** (60–3600), **`reboot_requires_no_user`** (default
  true), and **`max_install_attempts`** (1–5, default 2).
- When the gate **allows** an install and the agent advertises the
  **`patch-reboot-v1`** capability, the signed payload gains `max_attempts` and,
  if `reboot_policy != never`, a signed `reboot` block (policy, delay,
  `requires_no_user`, and — when a window is required — the bound
  `maintenance_window_id`/`ends_at`). Agents without the capability get neither
  field, so a mixed-version fleet is safe and older agents never reboot.
- The **agent** retries updates that fail with a retryable code up to
  `max_attempts` (WUA installs are idempotent per update, so nothing
  double-installs) and reports **per-update outcomes** (`identifier`,
  `result_code`, `hresult`, `attempts`). After installing it applies the reboot
  decision: consent wins first — if `requires_no_user` and a user is present the
  reboot is **deferred**; `if_required` is a no-op when no reboot is pending;
  otherwise the reboot is **scheduled** via the same `shutdown.exe /r` mechanism
  as power operations. The result is stored durably before the delayed reboot, so
  a restart never loses the outcome or re-installs (the agent's replay journal
  turns an interrupted command into a reported unknown-outcome, never a re-run).
- **Scheduled installs go through the same gate.** A `install_updates`
  scheduled task (issue #49) is evaluated against the effective policy before
  signing: its payload is narrowed to the approved subset and it is skipped for
  an agent whose policy blocks it (e.g. outside a required window). This is how
  "approved updates dispatch only inside policy windows" holds for automation as
  well as interactive dispatch.

## Audit

`patch_approval_policy.created` / `.revised` / `.deleted` (names and change notes
are digest-only), `patch_install.gated` (counts and outcome only), and
`patch_install.reboot_authorized` (the injected reboot policy, no update titles).
See [`AUDIT-EVENTS.md`](AUDIT-EVENTS.md).

## Rollout

Forward-only. Deploy migration `0033`/`0034` and the server, then canary agents
advertising `patch-reboot-v1`, then the dashboard. `0033` creates the two
`patch_approval_policies*` tables and adds nullable `timezone`/`recurrence` to
`maintenance_windows`; `0034` adds the reboot/retry columns to policy revisions
(all defaulted to the fail-safe `never`). Existing absolute windows, existing
installs, and older agents are unaffected — reboot injection is capability-gated
and default `never`, and policies are opt-in.

One intended behavior change: **scheduled `install_updates` tasks now honor the
approval policy and maintenance windows** (issue #53). A scheduled install that
was previously ungated is now narrowed to the approved subset and skipped when a
required window is inactive. Review existing patch schedules before deploying.

## Verification

- Server: `server/tests/test_patch_policies.py` covers CRUD, scope validation,
  most-specific resolution, deny/narrow/defer evaluation (including defer age and
  unknown-release fail-closed), the maintenance-window requirement with a
  recurring window, and opt-in passthrough; `server/tests/test_power_operations.py`
  confirms the window change does not regress power ops.
- Dashboard: `dashboard/test/patch-policies-core.test.ts` covers allowlisted,
  fail-closed parsing and formatters.
