# Live Patch Approval Policies Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an admin create, enable/disable, and delete patch approval policies from the `/patch-policies` dashboard page.

**Architecture:** Pure dashboard-only feature mirroring the signed-webhook manager: pure core (types/parsers/body-builders) → server-only proxy lib (`nodelinkApiRequest`) → pure route-core handlers (same-origin + session + admin gating + validation + error mapping) → thin Next.js API routes → a client component form/table. The server API already exposes create/revise/delete; no server or DB change. Enable/disable is a `PUT` revise that re-sends the loaded revision's rules + settings with only `enabled` flipped, so nothing is silently reset.

**Tech Stack:** Next.js (customized — see constraint), React client component, TypeScript, `node:test` + `node:assert/strict` for unit tests (run via `npm test`), lucide-react icons.

**Spec:** `docs/superpowers/specs/2026-09-09-patch-policies-live-page-design.md`

**Implementation constraint:** `dashboard/AGENTS.md` warns this is a customized Next.js. Before writing the API route files (Task 6) and client component (Task 7), read the route-handler and client-component guides under `dashboard/node_modules/next/dist/docs/`.

---

## File structure

- Create: `dashboard/src/lib/patch-policies-route-core.ts` — pure request handlers (auth, validation, error mapping). No Next imports.
- Modify: `dashboard/src/lib/patch-policies-core.ts` — extend types + parser with reboot round-trip fields; add pure body-builder/validator helpers.
- Modify: `dashboard/src/lib/patch-policies.ts` — add `createPatchPolicy`, `revisePatchPolicy`, `deletePatchPolicy` proxy calls.
- Create: `dashboard/src/app/api/patch-policies/route.ts` — `POST` create.
- Create: `dashboard/src/app/api/patch-policies/[policyId]/route.ts` — `PATCH` toggle, `DELETE`.
- Create: `dashboard/src/components/patch-policy-manager.tsx` — client form + register table.
- Modify: `dashboard/src/app/patch-policies/page.tsx` — pass `isAdmin` + policies into the client component.
- Modify: `dashboard/src/components/dashboard-shell.tsx:65-82` — add sidebar nav link.
- Test: `dashboard/test/patch-policies-core.test.ts` — extend (existing file, already in `npm test`).
- Test: `dashboard/test/patch-policies-route-core.test.ts` — new; must be added to the `test` script in `dashboard/package.json`.

---

### Task 1: Extend the pure core with reboot round-trip fields

**Files:**
- Modify: `dashboard/src/lib/patch-policies-core.ts:26-39` (type), `:126-164` (parser)
- Test: `dashboard/test/patch-policies-core.test.ts`

- [ ] **Step 1: Write the failing test**

Append to `dashboard/test/patch-policies-core.test.ts`:

```ts
test("patchPolicyFromUnknown captures reboot round-trip fields", () => {
  const parsed = patchPolicyFromUnknown({
    id: "p1", name: "Baseline", scope: "global", scope_id: null,
    enabled: true, created_at: "2026-09-09T10:00:00Z", current_version: 1,
    rule_count: 0, default_action: "deny", require_maintenance_window: false,
    reboot_policy: "if_required", reboot_delay_seconds: 900,
    reboot_requires_no_user: false, max_install_attempts: 3,
  });
  assert.equal(parsed?.reboot_delay_seconds, 900);
  assert.equal(parsed?.reboot_requires_no_user, false);
});

test("patchPolicyFromUnknown rejects an out-of-range reboot delay", () => {
  assert.equal(patchPolicyFromUnknown({
    id: "p1", name: "Baseline", scope: "global", scope_id: null,
    enabled: true, created_at: "2026-09-09T10:00:00Z", current_version: 1,
    rule_count: 0, default_action: "deny", require_maintenance_window: false,
    reboot_policy: "never", reboot_delay_seconds: 10,
    reboot_requires_no_user: true, max_install_attempts: 1,
  }), null);
});
```

Ensure the test file imports `patchPolicyFromUnknown` (add to the existing import from `../src/lib/patch-policies-core.ts` if missing).

- [ ] **Step 2: Run test to verify it fails**

Run: `cd dashboard && node --experimental-strip-types --test test/patch-policies-core.test.ts`
Expected: FAIL — `parsed?.reboot_delay_seconds` is `undefined`.

- [ ] **Step 3: Extend the type**

In `dashboard/src/lib/patch-policies-core.ts`, add two fields to `PatchApprovalPolicy` (after `reboot_policy: RebootPolicy;`, before `max_install_attempts`):

```ts
  reboot_policy: RebootPolicy;
  reboot_delay_seconds: number;
  reboot_requires_no_user: boolean;
  max_install_attempts: number;
```

- [ ] **Step 4: Extend the parser**

In `patchPolicyFromUnknown`, add validation inside the guard `if (...)` block (after the `reboot_policy` check, before `max_install_attempts`):

```ts
    || !rebootPolicies.has(value.reboot_policy as RebootPolicy)
    || !Number.isInteger(value.reboot_delay_seconds)
    || (value.reboot_delay_seconds as number) < 60
    || (value.reboot_delay_seconds as number) > 3600
    || typeof value.reboot_requires_no_user !== "boolean"
    || !Number.isInteger(value.max_install_attempts)
```

And add the two fields to the returned object (after `reboot_policy:`):

```ts
    reboot_policy: value.reboot_policy as RebootPolicy,
    reboot_delay_seconds: value.reboot_delay_seconds as number,
    reboot_requires_no_user: value.reboot_requires_no_user as boolean,
    max_install_attempts: value.max_install_attempts as number,
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd dashboard && node --experimental-strip-types --test test/patch-policies-core.test.ts`
Expected: PASS (all tests, including pre-existing).

- [ ] **Step 6: Commit**

```bash
git add dashboard/src/lib/patch-policies-core.ts dashboard/test/patch-policies-core.test.ts
git commit -m "feat(dashboard): carry reboot round-trip fields on patch policy type"
```

---

### Task 2: Add pure body-builder helpers to the core

These build the exact JSON bodies the server expects, so both the route-core and tests share one definition. `buildCreateBody` normalizes create-form input; `buildToggleBody` derives the revise `PUT` body from a loaded detail with only `enabled` flipped.

**Files:**
- Modify: `dashboard/src/lib/patch-policies-core.ts` (end of file, before `formatPatchScope`)
- Test: `dashboard/test/patch-policies-core.test.ts`

- [ ] **Step 1: Write the failing test**

Append to `dashboard/test/patch-policies-core.test.ts`:

```ts
test("buildToggleBody re-sends the loaded revision with enabled flipped", () => {
  const detail = {
    id: "p1", name: "Baseline", scope: "global" as const, scope_id: null,
    enabled: true, created_at: "2026-09-09T10:00:00Z", current_version: 2,
    rule_count: 1, default_action: "approve" as const,
    require_maintenance_window: true, reboot_policy: "if_required" as const,
    reboot_delay_seconds: 900, reboot_requires_no_user: false,
    max_install_attempts: 3,
    rules: [{
      key: "sec", action: "approve" as const,
      match: { classifications: ["Security"], severities: null, kb_ids: null },
      defer_days: null,
    }],
    revisions: [],
  };
  assert.deepEqual(buildToggleBody(detail, false), {
    enabled: false,
    default_action: "approve",
    require_maintenance_window: true,
    reboot_policy: "if_required",
    reboot_delay_seconds: 900,
    reboot_requires_no_user: false,
    max_install_attempts: 3,
    rules: detail.rules,
  });
});
```

Add `buildToggleBody` to the import from `../src/lib/patch-policies-core.ts`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd dashboard && node --experimental-strip-types --test test/patch-policies-core.test.ts`
Expected: FAIL — `buildToggleBody` is not exported.

- [ ] **Step 3: Implement the helpers**

Add to `dashboard/src/lib/patch-policies-core.ts` (before `formatPatchScope`):

```ts
export type PatchPolicyRevisionBody = {
  rules: PatchRule[];
  default_action: PatchDefaultAction;
  require_maintenance_window: boolean;
  reboot_policy: RebootPolicy;
  reboot_delay_seconds: number;
  reboot_requires_no_user: boolean;
  max_install_attempts: number;
};

export type PatchPolicyCreateBody = PatchPolicyRevisionBody & {
  name: string;
  scope: PatchScope;
  scope_id: string | null;
  enabled: boolean;
};

export type PatchPolicyToggleBody = PatchPolicyRevisionBody & { enabled: boolean };

export function buildToggleBody(
  detail: PatchApprovalPolicyDetail,
  enabled: boolean,
): PatchPolicyToggleBody {
  return {
    enabled,
    default_action: detail.default_action,
    require_maintenance_window: detail.require_maintenance_window,
    reboot_policy: detail.reboot_policy,
    reboot_delay_seconds: detail.reboot_delay_seconds,
    reboot_requires_no_user: detail.reboot_requires_no_user,
    max_install_attempts: detail.max_install_attempts,
    rules: detail.rules,
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd dashboard && node --experimental-strip-types --test test/patch-policies-core.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add dashboard/src/lib/patch-policies-core.ts dashboard/test/patch-policies-core.test.ts
git commit -m "feat(dashboard): add patch policy body-builder helpers"
```

---

### Task 3: Add proxy-lib mutation functions

**Files:**
- Modify: `dashboard/src/lib/patch-policies.ts`

- [ ] **Step 1: Add the three functions**

Append to `dashboard/src/lib/patch-policies.ts` (after `getAgentEffectivePatchPolicy`). Update the import from `@/lib/patch-policies-core` to also include `patchPolicyFromUnknown`, `type PatchPolicyCreateBody`, and `type PatchPolicyToggleBody`:

```ts
export async function createPatchPolicy(
  sessionToken: string,
  input: PatchPolicyCreateBody,
): Promise<PatchApprovalPolicy> {
  const value = await nodelinkApiRequest<unknown>("/api/v1/patch-approval/policies", {
    body: JSON.stringify(input), headers: { "Content-Type": "application/json" },
    method: "POST", sessionToken,
  });
  const policy = patchPolicyFromUnknown(value);
  if (!policy) throw new Error("The management service returned an invalid patch approval policy.");
  return policy;
}

export async function revisePatchPolicy(
  sessionToken: string,
  policyId: string,
  input: PatchPolicyToggleBody,
): Promise<PatchApprovalPolicy> {
  const value = await nodelinkApiRequest<unknown>(
    `/api/v1/patch-approval/policies/${encodeURIComponent(policyId)}`,
    {
      body: JSON.stringify(input), headers: { "Content-Type": "application/json" },
      method: "PUT", sessionToken,
    },
  );
  const policy = patchPolicyFromUnknown(value);
  if (!policy) throw new Error("The management service returned an invalid patch approval policy.");
  return policy;
}

export async function deletePatchPolicy(
  sessionToken: string,
  policyId: string,
): Promise<void> {
  await nodelinkApiRequest<unknown>(
    `/api/v1/patch-approval/policies/${encodeURIComponent(policyId)}`,
    { method: "DELETE", sessionToken },
  );
}
```

Note: the server `PUT`/`POST` return a `PatchApprovalPolicyDetailOut` (which includes `rules`/`revisions`), but `patchPolicyFromUnknown` reads only the summary fields it needs — extra fields are ignored. The `DELETE` returns 204 with no body; `nodelinkApiRequest` tolerates an empty body for a 2xx.

- [ ] **Step 2: Typecheck**

Run: `cd dashboard && npm run typecheck`
Expected: PASS (no type errors).

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/lib/patch-policies.ts
git commit -m "feat(dashboard): add patch policy create/revise/delete proxy calls"
```

---

### Task 4: Create the pure route-core handlers

Mirrors `dashboard/src/lib/webhook-route-core.ts`: same-origin check, session auth, **admin** gating, body validation, error mapping. All dependencies injected so it is testable without Next.

**Files:**
- Create: `dashboard/src/lib/patch-policies-route-core.ts`

- [ ] **Step 1: Write the file**

Create `dashboard/src/lib/patch-policies-route-core.ts`:

```ts
// SPDX-License-Identifier: AGPL-3.0-only

import { isSameOrigin, requestOrigin } from "./dashboard-auth-core.ts";
import {
  patchPolicyFromUnknown,
  buildToggleBody,
  type PatchApprovalPolicy,
  type PatchApprovalPolicyDetail,
  type PatchDefaultAction,
  type PatchPolicyCreateBody,
  type PatchScope,
  type RebootPolicy,
} from "./patch-policies-core.ts";

type Role = "readonly" | "operator" | "admin";
type RouteSession =
  | { kind: "anonymous" }
  | { kind: "unavailable" }
  | { kind: "authenticated"; operator: { role: Role }; sessionToken: string };
type SessionDependency = () => Promise<RouteSession>;

const scopes = new Set<PatchScope>(["global", "client", "site", "agent"]);
const defaults = new Set<PatchDefaultAction>(["approve", "deny"]);
const rebootPolicies = new Set<RebootPolicy>(["never", "if_required", "forced"]);

function json(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

function errorStatus(error: unknown): number {
  return error && typeof error === "object"
    && typeof (error as { status?: unknown }).status === "number"
    ? (error as { status: number }).status : 503;
}

function mappedError(error: unknown): Response {
  const status = errorStatus(error);
  if (status === 401) return json({ error: "Your session expired. Sign in again." }, 401);
  if (status === 403) return json({ error: "Your role cannot manage patch policies." }, 403);
  if (status === 404) return json({ error: "This policy no longer exists." }, 404);
  if (status === 409) return json({ error: "A policy with that name already exists for this scope." }, 409);
  if (status === 400 || status === 422) return json({ error: "Check the policy fields and scope target." }, 422);
  return json({ error: "The change could not be confirmed. Try again." }, 503);
}

async function authorizeAdmin(
  request: Request,
  getSession: SessionDependency,
): Promise<Response | { sessionToken: string }> {
  if (!isSameOrigin(
    request.headers.get("origin"),
    requestOrigin(request.url, request.headers.get("host")),
  )) return json({ error: "The request was rejected." }, 403);
  const session = await getSession().catch(() => ({ kind: "unavailable" } as const));
  if (session.kind === "anonymous") return json({ error: "Your session expired. Sign in again." }, 401);
  if (session.kind === "unavailable") return json({ error: "Session verification is unavailable." }, 503);
  return session.operator.role === "admin"
    ? { sessionToken: session.sessionToken }
    : json({ error: "Your role cannot manage patch policies." }, 403);
}

function isResponse(value: Response | { sessionToken: string }): value is Response {
  return value instanceof Response;
}

function validCreateBody(body: unknown): body is PatchPolicyCreateBody {
  if (typeof body !== "object" || body === null) return false;
  const b = body as Record<string, unknown>;
  const allowed = new Set([
    "name", "scope", "scope_id", "enabled", "rules", "default_action",
    "require_maintenance_window", "reboot_policy", "reboot_delay_seconds",
    "reboot_requires_no_user", "max_install_attempts",
  ]);
  if (Object.keys(b).some((key) => !allowed.has(key))) return false;
  if (typeof b.name !== "string" || b.name.trim().length < 1 || b.name.trim().length > 200) return false;
  if (!scopes.has(b.scope as PatchScope)) return false;
  const globalScope = b.scope === "global";
  if (globalScope ? b.scope_id !== null : (typeof b.scope_id !== "string" || (b.scope_id as string).length < 1 || (b.scope_id as string).length > 36)) return false;
  if (typeof b.enabled !== "boolean") return false;
  if (!Array.isArray(b.rules) || b.rules.length !== 0) return false; // v1: rules always []
  if (!defaults.has(b.default_action as PatchDefaultAction)) return false;
  if (typeof b.require_maintenance_window !== "boolean") return false;
  if (!rebootPolicies.has(b.reboot_policy as RebootPolicy)) return false;
  if (!Number.isInteger(b.reboot_delay_seconds) || (b.reboot_delay_seconds as number) < 60 || (b.reboot_delay_seconds as number) > 3600) return false;
  if (typeof b.reboot_requires_no_user !== "boolean") return false;
  if (!Number.isInteger(b.max_install_attempts) || (b.max_install_attempts as number) < 1 || (b.max_install_attempts as number) > 5) return false;
  return true;
}

export async function handlePatchPolicyCreate(
  request: Request,
  dependencies: {
    getSession: SessionDependency;
    createPolicy: (token: string, input: PatchPolicyCreateBody) => Promise<PatchApprovalPolicy>;
  },
): Promise<Response> {
  const authorized = await authorizeAdmin(request, dependencies.getSession);
  if (isResponse(authorized)) return authorized;
  const body = await request.json().catch(() => null);
  if (!validCreateBody(body)) {
    return json({ error: "Name, scope, and valid policy defaults are required." }, 400);
  }
  const normalized: PatchPolicyCreateBody = { ...body, name: body.name.trim() };
  try {
    const policy = patchPolicyFromUnknown(await dependencies.createPolicy(authorized.sessionToken, normalized));
    return policy
      ? json({ policy }, 201)
      : json({ error: "The service returned an invalid policy." }, 502);
  } catch (error) {
    return mappedError(error);
  }
}

export async function handlePatchPolicyToggle(
  request: Request,
  policyId: string,
  dependencies: {
    getSession: SessionDependency;
    getPolicy: (token: string, policyId: string) => Promise<PatchApprovalPolicyDetail>;
    revisePolicy: (token: string, policyId: string, input: ReturnType<typeof buildToggleBody>) => Promise<PatchApprovalPolicy>;
  },
): Promise<Response> {
  const authorized = await authorizeAdmin(request, dependencies.getSession);
  if (isResponse(authorized)) return authorized;
  const body = await request.json().catch(() => null) as Record<string, unknown> | null;
  if (!body || Object.keys(body).some((key) => key !== "enabled") || typeof body.enabled !== "boolean") {
    return json({ error: "The enabled flag is required." }, 400);
  }
  try {
    const detail = await dependencies.getPolicy(authorized.sessionToken, policyId);
    const toggleBody = buildToggleBody(detail, body.enabled as boolean);
    const policy = patchPolicyFromUnknown(await dependencies.revisePolicy(authorized.sessionToken, policyId, toggleBody));
    return policy
      ? json({ policy })
      : json({ error: "The service returned an invalid policy." }, 502);
  } catch (error) {
    return mappedError(error);
  }
}

export async function handlePatchPolicyDelete(
  request: Request,
  policyId: string,
  dependencies: {
    getSession: SessionDependency;
    deletePolicy: (token: string, policyId: string) => Promise<void>;
  },
): Promise<Response> {
  const authorized = await authorizeAdmin(request, dependencies.getSession);
  if (isResponse(authorized)) return authorized;
  try {
    await dependencies.deletePolicy(authorized.sessionToken, policyId);
    return json({ deleted: true });
  } catch (error) {
    return mappedError(error);
  }
}
```

- [ ] **Step 2: Typecheck**

Run: `cd dashboard && npm run typecheck`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/lib/patch-policies-route-core.ts
git commit -m "feat(dashboard): add patch policy route-core handlers"
```

---

### Task 5: Test the route-core handlers

**Files:**
- Create: `dashboard/test/patch-policies-route-core.test.ts`
- Modify: `dashboard/package.json` (add the file to the `test` script)

- [ ] **Step 1: Write the test file**

Create `dashboard/test/patch-policies-route-core.test.ts`:

```ts
// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";

import {
  handlePatchPolicyCreate,
  handlePatchPolicyDelete,
  handlePatchPolicyToggle,
} from "../src/lib/patch-policies-route-core.ts";

const policy = {
  id: "p1", name: "Baseline", scope: "global" as const, scope_id: null,
  enabled: true, created_at: "2026-09-09T10:00:00Z", current_version: 1,
  rule_count: 0, default_action: "deny" as const, require_maintenance_window: false,
  reboot_policy: "never" as const, reboot_delay_seconds: 300,
  reboot_requires_no_user: true, max_install_attempts: 2,
};

const detail = { ...policy, current_version: 2, rules: [], revisions: [] };

const createBody = {
  name: "Baseline", scope: "global", scope_id: null, enabled: true,
  rules: [], default_action: "deny", require_maintenance_window: false,
  reboot_policy: "never", reboot_delay_seconds: 300,
  reboot_requires_no_user: true, max_install_attempts: 2,
};

function request(path: string, body: unknown, origin = "https://dashboard.test", method = "POST") {
  return new Request(`https://dashboard.test${path}`, {
    method,
    headers: { "Content-Type": "application/json", Origin: origin },
    body: JSON.stringify(body),
  });
}

const adminSession = async () => ({
  kind: "authenticated" as const,
  operator: { role: "admin" as const }, sessionToken: "server-secret",
});

test("create rejects cross-origin and non-admin requests", async () => {
  const readonly = {
    getSession: async () => ({
      kind: "authenticated" as const,
      operator: { role: "readonly" as const }, sessionToken: "server-secret",
    }),
    createPolicy: async () => policy,
  };
  assert.equal((await handlePatchPolicyCreate(
    request("/api/patch-policies", createBody, "https://evil.test"), readonly,
  )).status, 403);
  assert.equal((await handlePatchPolicyCreate(
    request("/api/patch-policies", createBody), readonly,
  )).status, 403);
});

test("create forwards normalized input and never leaks the session token", async () => {
  let token = "";
  let input: unknown;
  const response = await handlePatchPolicyCreate(
    request("/api/patch-policies", { ...createBody, name: "  Baseline  " }),
    {
      getSession: adminSession,
      createPolicy: async (receivedToken, receivedInput) => {
        token = receivedToken; input = receivedInput; return policy;
      },
    },
  );
  assert.equal(response.status, 201);
  assert.equal(token, "server-secret");
  assert.equal((input as { name: string }).name, "Baseline");
  assert.doesNotMatch(JSON.stringify(await response.json()), /server-secret/);
});

test("create rejects a non-empty rules list in v1", async () => {
  const response = await handlePatchPolicyCreate(
    request("/api/patch-policies", { ...createBody, rules: [{ key: "x" }] }),
    { getSession: adminSession, createPolicy: async () => policy },
  );
  assert.equal(response.status, 400);
});

test("toggle re-sends the loaded revision with enabled flipped", async () => {
  let revised: unknown;
  const response = await handlePatchPolicyToggle(
    request("/api/patch-policies/p1", { enabled: false }, undefined, "PATCH"),
    "p1",
    {
      getSession: adminSession,
      getPolicy: async () => detail,
      revisePolicy: async (_token, _id, receivedBody) => { revised = receivedBody; return { ...policy, enabled: false }; },
    },
  );
  assert.equal(response.status, 200);
  assert.equal((revised as { enabled: boolean }).enabled, false);
  assert.deepEqual((revised as { rules: unknown[] }).rules, []);
  assert.equal((revised as { default_action: string }).default_action, "deny");
});

test("toggle rejects a body with unexpected keys", async () => {
  const response = await handlePatchPolicyToggle(
    request("/api/patch-policies/p1", { enabled: true, name: "x" }, undefined, "PATCH"),
    "p1",
    { getSession: adminSession, getPolicy: async () => detail, revisePolicy: async () => policy },
  );
  assert.equal(response.status, 400);
});

test("delete maps a 404 from the service", async () => {
  const response = await handlePatchPolicyDelete(
    request("/api/patch-policies/p1", {}, undefined, "DELETE"),
    "p1",
    {
      getSession: adminSession,
      deletePolicy: async () => { throw Object.assign(new Error("gone"), { status: 404 }); },
    },
  );
  assert.equal(response.status, 404);
});
```

- [ ] **Step 2: Register the test file in the runner**

In `dashboard/package.json`, append ` test/patch-policies-route-core.test.ts` to the end of the `"test"` script's file list (before the closing quote).

- [ ] **Step 3: Run the test to verify it passes**

Run: `cd dashboard && node --experimental-strip-types --test test/patch-policies-route-core.test.ts`
Expected: PASS (6 tests).

- [ ] **Step 4: Commit**

```bash
git add dashboard/test/patch-policies-route-core.test.ts dashboard/package.json
git commit -m "test(dashboard): cover patch policy route-core handlers"
```

---

### Task 6: Wire the Next.js API routes

Read `dashboard/node_modules/next/dist/docs/` route-handler guidance first if the async-`params` context shape differs from the webhook example below.

**Files:**
- Create: `dashboard/src/app/api/patch-policies/route.ts`
- Create: `dashboard/src/app/api/patch-policies/[policyId]/route.ts`

- [ ] **Step 1: Create the collection route**

Create `dashboard/src/app/api/patch-policies/route.ts`:

```ts
// SPDX-License-Identifier: AGPL-3.0-only
import type { NextRequest } from "next/server";
import { getDashboardSession } from "@/lib/dashboard-session";
import { createPatchPolicy } from "@/lib/patch-policies";
import { handlePatchPolicyCreate } from "@/lib/patch-policies-route-core";

export function POST(request: NextRequest) {
  return handlePatchPolicyCreate(request, {
    getSession: getDashboardSession,
    createPolicy: createPatchPolicy,
  });
}
```

- [ ] **Step 2: Create the item route**

Create `dashboard/src/app/api/patch-policies/[policyId]/route.ts`:

```ts
// SPDX-License-Identifier: AGPL-3.0-only
import type { NextRequest } from "next/server";
import { getDashboardSession } from "@/lib/dashboard-session";
import { deletePatchPolicy, getPatchPolicy, revisePatchPolicy } from "@/lib/patch-policies";
import {
  handlePatchPolicyDelete,
  handlePatchPolicyToggle,
} from "@/lib/patch-policies-route-core";

type Context = { params: Promise<{ policyId: string }> };

export async function PATCH(request: NextRequest, context: Context) {
  const { policyId } = await context.params;
  return handlePatchPolicyToggle(request, policyId, {
    getSession: getDashboardSession,
    getPolicy: getPatchPolicy,
    revisePolicy: revisePatchPolicy,
  });
}

export async function DELETE(request: NextRequest, context: Context) {
  const { policyId } = await context.params;
  return handlePatchPolicyDelete(request, policyId, {
    getSession: getDashboardSession,
    deletePolicy: deletePatchPolicy,
  });
}
```

- [ ] **Step 3: Typecheck**

Run: `cd dashboard && npm run typecheck`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add dashboard/src/app/api/patch-policies
git commit -m "feat(dashboard): add patch policy API routes"
```

---

### Task 7: Build the client manager component

Read `dashboard/node_modules/next/dist/docs/` client-component guidance first. This reuses the CSS classes already used by the read-only page (`enrollment-panel`, `enrollment-table-wrap`, `monitoring-status`, `enrollment-empty`) plus the form/action classes from the webhook manager.

**Files:**
- Create: `dashboard/src/components/patch-policy-manager.tsx`

- [ ] **Step 1: Write the component**

Create `dashboard/src/components/patch-policy-manager.tsx`:

```tsx
// SPDX-License-Identifier: AGPL-3.0-only
"use client";

import { LoaderCircle, Plus, ShieldCheck, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { formatMonitoringTimestamp } from "@/lib/monitoring-core";
import {
  formatPatchScope,
  type PatchApprovalPolicy,
  type PatchDefaultAction,
  type PatchScope,
  type RebootPolicy,
} from "@/lib/patch-policies-core";

const scopeOptions: Array<{ value: PatchScope; label: string }> = [
  { value: "global", label: "Global (all managed endpoints)" },
  { value: "client", label: "Client" },
  { value: "site", label: "Site" },
  { value: "agent", label: "Endpoint" },
];

export function PatchPolicyManager({
  initialPolicies,
  canAdmin,
}: {
  initialPolicies: PatchApprovalPolicy[];
  canAdmin: boolean;
}) {
  const router = useRouter();
  const [policies, setPolicies] = useState(initialPolicies);
  const [name, setName] = useState("");
  const [scope, setScope] = useState<PatchScope>("global");
  const [scopeId, setScopeId] = useState("");
  const [defaultAction, setDefaultAction] = useState<PatchDefaultAction>("deny");
  const [requireWindow, setRequireWindow] = useState(false);
  const [rebootPolicy, setRebootPolicy] = useState<RebootPolicy>("never");
  const [rebootDelay, setRebootDelay] = useState(300);
  const [rebootRequiresNoUser, setRebootRequiresNoUser] = useState(true);
  const [maxAttempts, setMaxAttempts] = useState(2);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState("");

  async function responseBody<T>(response: Response): Promise<T> {
    const body = await response.json().catch(() => null) as (T & { error?: string }) | null;
    if (!response.ok || !body) throw new Error(body?.error ?? "The change could not be confirmed.");
    return body;
  }

  async function create(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("create");
    setError("");
    try {
      const response = await fetch("/api/patch-policies", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          scope,
          scope_id: scope === "global" ? null : scopeId.trim(),
          enabled: true,
          rules: [],
          default_action: defaultAction,
          require_maintenance_window: requireWindow,
          reboot_policy: rebootPolicy,
          reboot_delay_seconds: rebootDelay,
          reboot_requires_no_user: rebootRequiresNoUser,
          max_install_attempts: maxAttempts,
        }),
      });
      const body = await responseBody<{ policy: PatchApprovalPolicy }>(response);
      setPolicies((current) => [...current, body.policy].sort((a, b) => a.name.localeCompare(b.name)));
      setName("");
      setScopeId("");
      router.refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The policy could not be created.");
    } finally {
      setBusy(null);
    }
  }

  async function toggle(policy: PatchApprovalPolicy) {
    setBusy(`toggle:${policy.id}`);
    setError("");
    try {
      const response = await fetch(`/api/patch-policies/${encodeURIComponent(policy.id)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !policy.enabled }),
      });
      const body = await responseBody<{ policy: PatchApprovalPolicy }>(response);
      setPolicies((current) => current.map((item) => (item.id === policy.id ? body.policy : item)));
      router.refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The policy could not be updated.");
    } finally {
      setBusy(null);
    }
  }

  async function remove(policy: PatchApprovalPolicy) {
    if (!window.confirm(`Delete ${policy.name}? Endpoints it governs revert to Exempt.`)) return;
    setBusy(`delete:${policy.id}`);
    setError("");
    try {
      const response = await fetch(`/api/patch-policies/${encodeURIComponent(policy.id)}`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
      });
      await responseBody<{ deleted: true }>(response);
      setPolicies((current) => current.filter((item) => item.id !== policy.id));
      router.refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The policy could not be deleted.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      {canAdmin ? (
        <section className="enrollment-panel">
          <header><div><span>New policy</span><h2>Create a patch approval policy</h2><small>An empty rule set lets every update fall to the default action. Add rules later.</small></div><Plus size={19} /></header>
          <form onSubmit={create}>
            <label><span>Name</span><input value={name} onChange={(e) => setName(e.target.value)} maxLength={200} placeholder="Baseline" required /></label>
            <label><span>Scope</span><select value={scope} onChange={(e) => setScope(e.target.value as PatchScope)}>{scopeOptions.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}</select></label>
            {scope !== "global" ? <label><span>{formatPatchScope(scope)} id</span><input value={scopeId} onChange={(e) => setScopeId(e.target.value)} maxLength={36} placeholder="target id" required /></label> : null}
            <label><span>Default action</span><select value={defaultAction} onChange={(e) => setDefaultAction(e.target.value as PatchDefaultAction)}><option value="deny">Deny unmatched updates</option><option value="approve">Approve unmatched updates</option></select></label>
            <label><input type="checkbox" checked={requireWindow} onChange={(e) => setRequireWindow(e.target.checked)} /><span>Require an active maintenance window to install</span></label>
            <label><span>Reboot policy</span><select value={rebootPolicy} onChange={(e) => setRebootPolicy(e.target.value as RebootPolicy)}><option value="never">Never</option><option value="if_required">If required</option><option value="forced">Forced</option></select></label>
            <label><span>Reboot delay (seconds)</span><input type="number" min={60} max={3600} value={rebootDelay} onChange={(e) => setRebootDelay(Number(e.target.value))} /></label>
            <label><input type="checkbox" checked={rebootRequiresNoUser} onChange={(e) => setRebootRequiresNoUser(e.target.checked)} /><span>Only reboot when no user is signed in</span></label>
            <label><span>Max install attempts</span><input type="number" min={1} max={5} value={maxAttempts} onChange={(e) => setMaxAttempts(Number(e.target.value))} /></label>
            <button type="submit" disabled={busy === "create"}>{busy === "create" ? <LoaderCircle className="spin" size={15} /> : <ShieldCheck size={15} />} Create policy</button>
          </form>
        </section>
      ) : null}

      <section className="enrollment-panel">
        <header><div><span>Policy register</span><h2>{policies.length} policies</h2><small>Current revisions only; each edit appends an auditable version.</small></div><ShieldCheck size={19} /></header>
        {policies.length ? (
          <div className="enrollment-table-wrap">
            <table>
              <thead><tr><th>Policy</th><th>Scope</th><th>Status</th><th>Default</th><th>Rules</th><th>Revision</th><th>Created (UTC)</th>{canAdmin ? <th>Actions</th> : null}</tr></thead>
              <tbody>
                {policies.map((policy) => (
                  <tr key={policy.id}>
                    <td><strong>{policy.name}</strong><code>{policy.id}</code></td>
                    <td><strong>{formatPatchScope(policy.scope)}</strong><code>{policy.scope_id ?? "All managed endpoints"}</code></td>
                    <td><span className={`monitoring-status ${policy.enabled ? "enabled" : "disabled"}`}>{policy.enabled ? "Enabled" : "Disabled"}</span></td>
                    <td>{policy.default_action === "approve" ? "Approve" : "Deny"}</td>
                    <td>{policy.rule_count}</td>
                    <td><code>v{policy.current_version}</code></td>
                    <td>{formatMonitoringTimestamp(policy.created_at)}</td>
                    {canAdmin ? (
                      <td>
                        <button type="button" onClick={() => toggle(policy)} disabled={Boolean(busy)}>{policy.enabled ? "Disable" : "Enable"}</button>
                        <button className="danger" type="button" onClick={() => remove(policy)} disabled={Boolean(busy)}><Trash2 size={13} /> Delete</button>
                      </td>
                    ) : null}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="enrollment-empty"><ShieldCheck size={24} /><h3>No patch approval policies yet</h3><p>{canAdmin ? "Create a policy so governed endpoints leave the Exempt state." : "Until a policy is created, Windows Update installs proceed without an approval gate."}</p></div>
        )}
      </section>
      {error ? <p className="alert-action-error" role="alert">{error}</p> : null}
    </>
  );
}
```

- [ ] **Step 2: Typecheck**

Run: `cd dashboard && npm run typecheck`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/components/patch-policy-manager.tsx
git commit -m "feat(dashboard): add patch policy manager component"
```

---

### Task 8: Make the page render the manager

**Files:**
- Modify: `dashboard/src/app/patch-policies/page.tsx`

- [ ] **Step 1: Replace the static table with the manager**

Rewrite `dashboard/src/app/patch-policies/page.tsx` so it keeps the header/banner but delegates the register to the client component, passing `isAdmin`:

```tsx
// SPDX-License-Identifier: AGPL-3.0-only

import { Layers3 } from "lucide-react";
import { redirect } from "next/navigation";

import { PatchPolicyManager } from "@/components/patch-policy-manager";
import { getDashboardSession } from "@/lib/dashboard-session";
import { type PatchApprovalPolicy } from "@/lib/patch-policies-core";
import { getPatchPolicies } from "@/lib/patch-policies";

export const dynamic = "force-dynamic";

export default async function PatchPoliciesPage() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  let policies: PatchApprovalPolicy[] | null = null;
  const result = await Promise.allSettled([getPatchPolicies(session.sessionToken)]);
  if (result[0].status === "fulfilled") policies = result[0].value;

  return (
    <>
      <header className="enrollment-page-head">
        <div>
          <span>Versioned configuration</span>
          <h1>Patch approval policies</h1>
          <p>
            Windows Update approval rules across global, client, site, and endpoint scopes.
            Installs are gated server-side against the most specific policy.
          </p>
        </div>
        <span className="monitoring-readonly-note">{session.operator.role === "admin" ? "Administrator" : "Read-only"}</span>
      </header>

      <section className="setup-boundary-banner">
        <Layers3 aria-hidden="true" size={22} />
        <div>
          <strong>Most-specific policy wins</strong>
          <span>
            The single most specific policy that targets an endpoint governs its installs. Unmatched
            updates fall to the policy default. With no policy, installs proceed unchanged.
          </span>
        </div>
      </section>

      {policies === null ? (
        <div className="enrollment-empty" role="alert">
          <h3>Patch approval policies could not be loaded</h3>
          <p>No policies are shown because the server response could not be verified.</p>
        </div>
      ) : (
        <PatchPolicyManager initialPolicies={policies} canAdmin={session.operator.role === "admin"} />
      )}
    </>
  );
}
```

- [ ] **Step 2: Typecheck**

Run: `cd dashboard && npm run typecheck`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/app/patch-policies/page.tsx
git commit -m "feat(dashboard): render patch policy manager on the page"
```

---

### Task 9: Add the sidebar nav link

**Files:**
- Modify: `dashboard/src/components/dashboard-shell.tsx:65-82`

- [ ] **Step 1: Add the nav item**

In the `navItems` array, add an entry immediately after the "Patch compliance" line (`dashboard-shell.tsx:75`). Reuse the already-imported `Shield` icon:

```ts
  { label: "Patch compliance", icon: Shield, count: null, href: "/patch-compliance" },
  { label: "Patch policies", icon: Shield, count: null, href: "/patch-policies" },
```

- [ ] **Step 2: Typecheck**

Run: `cd dashboard && npm run typecheck`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add dashboard/src/components/dashboard-shell.tsx
git commit -m "feat(dashboard): link patch policies in the sidebar"
```

---

### Task 10: Full verification

- [ ] **Step 1: Run the whole dashboard test suite**

Run: `cd dashboard && npm test`
Expected: PASS, including `patch-policies-core` and the new `patch-policies-route-core`.

- [ ] **Step 2: Typecheck and lint**

Run: `cd dashboard && npm run typecheck && npm run lint`
Expected: PASS.

- [ ] **Step 3: Manual smoke (requires a running server + admin session)**

1. Start the dashboard (`npm run dev`) pointed at the server (`NODELINK_API_BASE_URL`).
2. Sign in as an admin, open the sidebar → **Patch policies**.
3. Create a Global policy named "Baseline", default action **Deny**. Confirm it appears in the register with `v1`, Enabled.
4. Click **Disable**, confirm status flips and revision increments (`v2`); click **Enable** again.
5. Click **Delete**, confirm it disappears.
6. Sign in as a readonly user: the form and action buttons are absent; the register is still visible.

- [ ] **Step 4: Final commit (if any lint/format fixes were needed)**

```bash
git add -A
git commit -m "chore(dashboard): finalize patch policy management"
```
