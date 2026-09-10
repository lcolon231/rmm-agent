# Live patch approval policies page — design

- **Date:** 2026-09-09
- **Scope chosen:** B — Create + enable/disable + delete (per-rule editing deferred)
- **Status:** approved for planning

## Problem

The dashboard route `/patch-policies` is read-only (labels itself "Read-only
foundation") and is not linked in the sidebar, so an admin cannot create a patch
approval policy from the UI. With no policy in force, every endpoint resolves to
`Exempt` on the patch-compliance report and Windows Update installs proceed
without an approval gate. Admins need to create, enable/disable, and delete
policies from the dashboard.

## Goal / non-goals

**Goal:** an admin can create a patch approval policy, toggle its `enabled`
flag, and delete it, entirely from `/patch-policies`. Read-only users keep the
current inventory view.

**Non-goals (explicit):**
- Per-rule editing / a rule builder (the "scope C" fast-follow).
- Viewing or diffing revision history in the UI.
- Bulk actions.
- Any change to `/patch-compliance` or the agent-side Windows Update scan.

## Key server facts (no server change required)

All endpoints already exist on the FastAPI server under `/api/v1`
(`server/app/api/management.py`), each requiring `OperatorRole.operator` or
higher (admins satisfy this):

- `POST /patch-approval/policies` — create (`create_patch_policy`, line ~2860).
- `GET /patch-approval/policies` and `/{id}` — list / detail (readonly).
- `PUT /patch-approval/policies/{id}` — **revise** (`revise_patch_policy`,
  line ~2963): creates a new revision that **fully replaces** the rule set and
  all revision-level settings, and optionally flips `enabled`.
- `DELETE /patch-approval/policies/{id}` — delete (line ~3017).

There is **no lightweight enable/disable toggle**: toggling goes through `PUT`,
which replaces the whole revision. This is the central design constraint below.

Request schema (`server/app/schemas/patch_policies.py`):
- `PatchApprovalPolicyCreate`: `name`, `scope`, `scope_id?`, `enabled`,
  `rules: list[PatchRule] = []`, `default_action` (approve|deny, default deny),
  `require_maintenance_window`, plus `_RebootSettings` (`reboot_policy`,
  `reboot_delay_seconds` 60–3600, `reboot_requires_no_user`,
  `max_install_attempts` 1–5), optional `change_note`.
- `PatchApprovalPolicyUpdate` (the `PUT` body): same revision-level fields
  (`rules`, `default_action`, `require_maintenance_window`, `_RebootSettings`),
  optional `enabled`, optional `change_note`. `name`/`scope` are fixed at
  create time and not part of a revision.

## Architecture (mirror the webhook-manager pattern)

This reuses the established pattern from the signed-webhooks feature:
pure core (validation/parsing) → server-only proxy lib → route-core handlers →
thin Next.js API routes → client component. All work is under `dashboard/`.

| Layer | File | Change |
|---|---|---|
| Server lib (proxy) | `dashboard/src/lib/patch-policies.ts` | Add `createPatchPolicy`, `revisePatchPolicy`, `deletePatchPolicy`; reuse existing `getPatchPolicy` for the toggle round-trip. |
| Pure core | `dashboard/src/lib/patch-policies-core.ts` | Extend types + parser with `reboot_delay_seconds` and `reboot_requires_no_user`; add pure helpers to build/validate the create body and the toggle (revise) body from a loaded detail. |
| Route core (new) | `dashboard/src/lib/patch-policies-route-core.ts` | `handlePatchPolicyCreate`, `handlePatchPolicyToggle`, `handlePatchPolicyDelete`: same-origin check, session auth, admin gating, body validation, error mapping. Pure and testable with injected dependencies. |
| API routes (new) | `dashboard/src/app/api/patch-policies/route.ts` (POST); `dashboard/src/app/api/patch-policies/[policyId]/route.ts` (PATCH toggle, DELETE) | Thin wiring of `getDashboardSession` + lib functions into the route-core handlers. |
| Client component (new) | `dashboard/src/components/patch-policy-manager.tsx` | The "New policy" form plus the register table with enable/disable and delete actions. |
| Page | `dashboard/src/app/patch-policies/page.tsx` | Pass `isAdmin` + initial policies into the client component; non-admins keep the current read-only table. |
| Nav | `dashboard/src/components/dashboard-shell.tsx` | Add a "Patch policies" → `/patch-policies` sidebar link (currently missing). |

## Data flow

**Create:** form → `POST /api/patch-policies` → route-core (same-origin +
admin + validate) → `createPatchPolicy(token, body)` → server `POST` → 201
detail → UI prepends row and resets the form.

**Enable/disable (round-trip):** row toggle → `PATCH /api/patch-policies/{id}`
`{ enabled }` → route-core calls `getPatchPolicy(token, id)` to load the current
revision, then `revisePatchPolicy(token, id, body)` re-sending *that revision's*
`rules` + all revision-level settings with only `enabled` flipped → server
`PUT` → updated detail → UI updates the row. Re-sending the current rules and
reboot settings is what prevents `PUT` from resetting them to schema defaults;
this is why the parser must capture the reboot fields.

**Delete:** row action → confirm → `DELETE /api/patch-policies/{id}` →
`deletePatchPolicy(token, id)` → 204 → UI removes the row.

## Create form fields (v1)

Name; Scope (Global / Client / Site / Endpoint) + target id (shown and required
for non-global scopes, validated server-side); `default_action`
(**Approve / Deny** — decides Compliant vs Non-compliant on the report);
Require maintenance window (toggle); Reboot policy (Never / If required /
Forced) + delay seconds (60–3600) + requires-no-user (toggle); Max install
attempts (1–5); Enabled (toggle); optional change note. **`rules` is always
sent as `[]`** — no per-rule builder in v1.

## Auth, roles, concurrency

- **Admin-gated** in the dashboard route-core (matches intent and the webhook
  precedent). The server independently enforces `operator`+.
- Session flows through the existing cookie-based `getDashboardSession`,
  proxied to the server with the session token. No new auth mechanism.
- **No optimistic-concurrency tokens** — the server's patch-policy endpoints do
  not accept `request_id`/`expected_version` (unlike webhooks). Toggle is
  read-then-write; the small race window is acceptable for a low-frequency
  admin action. Recorded as a deliberate decision.

## Error handling

Reuse the webhook route-core mapping:
- 401 → "Your session expired. Sign in again."
- 403 → "Your role cannot manage patch policies."
- 404 → "This policy no longer exists."
- 409 → "A policy with that name already exists for this scope."
- 400/422 → "Check the policy fields and scope target."
- otherwise → 503 "The change could not be confirmed. Try again."

Parsers fail closed (return null → surface 502) on malformed server responses,
matching the existing `*FromUnknown` convention.

## Testing

- `dashboard/test/patch-policies-route-core.test.ts` (new, Vitest): auth gating,
  same-origin rejection, body validation, the toggle round-trip (asserts the
  loaded rules and reboot settings are preserved in the `PUT` body), and error
  mapping — all with injected fake dependencies. Mirrors
  `dashboard/test/webhook-route-core.test.ts`.
- `dashboard/test/patch-policies-core.test.ts`: extend for the new reboot fields
  and the body-builder/validator helpers.
- No server tests (no server change).

## Implementation constraint

`dashboard/AGENTS.md` warns this is a customized Next.js. Before writing route
or client-component code, read the relevant route-handler / client-component
guides under `node_modules/next/dist/docs/`.

## Follow-ups (out of this spec)

- Scope C: per-rule editor with faithful round-trip of existing rules.
- Investigate why the two Nodelink endpoints show "No trusted scan" (agent-side
  Windows Update inventory), needed before any policy yields a compliant state.
