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


// --------------------------------------------------------------------------- //
// Coverage extension: shared session, role, validation, and mapping behaviour
// --------------------------------------------------------------------------- //
type PPRole = "readonly" | "operator" | "admin";
type PPSession =
  | { kind: "anonymous" } | { kind: "unavailable" }
  | { kind: "authenticated"; operator: { role: PPRole }; sessionToken: string };
const ppSentinel = "SENTINEL-must-not-leak";

type PPCase = {
  name: string; method: string; body: unknown; invalid?: unknown; successStatus: number;
  run: (req: Request, getSession: () => Promise<PPSession>, api: (...a: unknown[]) => Promise<unknown>) => Promise<Response>;
};
const ppCases: PPCase[] = [
  {
    name: "create", method: "POST", body: createBody, invalid: { ...createBody, extra: 1 }, successStatus: 201,
    run: (req, getSession, api) => handlePatchPolicyCreate(req, { getSession, createPolicy: api as never }),
  },
  {
    name: "toggle", method: "POST", body: { enabled: false }, invalid: { enabled: "no" }, successStatus: 200,
    run: (req, getSession, api) => handlePatchPolicyToggle(req, "p1", {
      getSession, getPolicy: (async () => detail) as never, revisePolicy: api as never,
    }),
  },
  {
    name: "delete", method: "DELETE", body: {}, successStatus: 200,
    run: (req, getSession, api) => handlePatchPolicyDelete(req, "p1", { getSession, deletePolicy: api as never }),
  },
];

for (const c of ppCases) {
  const make = (origin?: string) => request("/x", c.body, origin, c.method);
  const okValue = () => (c.name === "delete" ? undefined : { ...policy, internal_token: ppSentinel });

  test(`patch policy ${c.name}: no usable session never reaches the API`, async () => {
    const sessions: Array<[number, () => Promise<PPSession>]> = [
      [401, async () => ({ kind: "anonymous" })],
      [503, async () => ({ kind: "unavailable" })],
      [503, async () => { throw new Error("boom"); }],
    ];
    for (const [status, getSession] of sessions) {
      let calls = 0;
      const res = await c.run(make(), getSession, async () => { calls += 1; return okValue(); });
      assert.equal(res.status, status);
      assert.equal(calls, 0);
    }
  });

  test(`patch policy ${c.name}: operator and readonly roles are rejected without forwarding`, async () => {
    let calls = 0;
    for (const role of ["readonly", "operator"] as const) {
      const res = await c.run(make(), async () => ({ kind: "authenticated", operator: { role }, sessionToken: "t" }),
        async () => { calls += 1; return okValue(); });
      assert.equal(res.status, 403);
    }
    assert.equal((await c.run(make("https://evil.test"), adminSession, async () => { calls += 1; return okValue(); })).status, 403);
    assert.equal(calls, 0);
  });

  test(`patch policy ${c.name}: allowlists success and maps upstream failures`, async () => {
    const ok = await c.run(make(), adminSession, async () => okValue());
    assert.equal(ok.status, c.successStatus);
    assert.doesNotMatch(JSON.stringify(await ok.json()), /server-secret|SENTINEL/);
    const expected: Array<[number, number]> = [
      [401, 401], [403, 403], [404, 404], [409, 409], [400, 422], [422, 422], [500, 503],
    ];
    for (const [upstream, mapped] of expected) {
      const res = await c.run(make(), adminSession, async () => {
        throw Object.assign(new Error(ppSentinel), { status: upstream });
      });
      assert.equal(res.status, mapped);
      assert.doesNotMatch(JSON.stringify(await res.json()), /SENTINEL/);
    }
    assert.equal((await c.run(make(), adminSession, async () => { throw new Error(ppSentinel); })).status, 503);
    if (c.name !== "delete") {
      const bad = await c.run(make(), adminSession, async () => ({ junk: ppSentinel }));
      assert.equal(bad.status, 502);
      assert.doesNotMatch(JSON.stringify(await bad.json()), /SENTINEL/);
    }
  });

  if (c.invalid !== undefined) {
    test(`patch policy ${c.name}: invalid bodies never reach the API`, async () => {
      let calls = 0;
      const api = async () => { calls += 1; return okValue(); };
      assert.equal((await c.run(request("/x", c.invalid, undefined, c.method), adminSession, api)).status, 400);
      assert.equal((await c.run(request("/x", null, undefined, c.method), adminSession, api)).status, 400);
      assert.equal(calls, 0);
    });
  }
}

test("patch policy create validates every field of the body", async () => {
  let calls = 0;
  const deps = { getSession: adminSession, createPolicy: async () => { calls += 1; return policy; } };
  const bad: Array<Record<string, unknown>> = [
    { name: "  " }, { name: "x".repeat(201) }, { name: 5 }, { scope: "planet" },
    { scope: "global", scope_id: "x" }, { scope: "client", scope_id: null },
    { scope: "client", scope_id: "" }, { scope: "client", scope_id: "x".repeat(37) },
    { enabled: "yes" }, { rules: [{}] }, { rules: "none" }, { default_action: "maybe" },
    { require_maintenance_window: 1 }, { reboot_policy: "sometimes" },
    { reboot_delay_seconds: 59 }, { reboot_delay_seconds: 3601 }, { reboot_delay_seconds: 90.5 },
    { reboot_requires_no_user: "y" }, { max_install_attempts: 0 }, { max_install_attempts: 6 },
  ];
  for (const patch of bad) {
    const res = await handlePatchPolicyCreate(request("/x", { ...createBody, ...patch }), deps);
    assert.equal(res.status, 400, JSON.stringify(patch));
  }
  assert.equal((await handlePatchPolicyCreate(request("/x", "text"), deps)).status, 400);
  assert.equal(calls, 0);

  let input: unknown;
  const scoped = await handlePatchPolicyCreate(
    request("/x", { ...createBody, name: "  Site policy ", scope: "site", scope_id: "site-1" }),
    { getSession: adminSession, createPolicy: async (_t, received) => { input = received; return policy; } },
  );
  assert.equal(scoped.status, 201);
  assert.deepEqual(input, { ...createBody, name: "Site policy", scope: "site", scope_id: "site-1" });
});

test("patch policy toggle surfaces a failing policy load and never revises", async () => {
  let revised = 0;
  const res = await handlePatchPolicyToggle(request("/x", { enabled: true }), "p1", {
    getSession: adminSession,
    getPolicy: async () => { throw Object.assign(new Error("gone"), { status: 404 }); },
    revisePolicy: async () => { revised += 1; return policy; },
  });
  assert.equal(res.status, 404);
  assert.equal(revised, 0);
});
