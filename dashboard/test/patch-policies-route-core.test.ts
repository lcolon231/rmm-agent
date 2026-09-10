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
