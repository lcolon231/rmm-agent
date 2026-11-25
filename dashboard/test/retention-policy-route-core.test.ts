// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";

import { handleRetentionPolicyRequest } from "../src/lib/retention-policy-route-core.ts";
import { policyPayload } from "./support/retention-policy-fixture.ts";

const ORIGIN = "https://dashboard.example.test";
type Role = "readonly" | "operator" | "admin";

function session(role: Role = "admin") {
  return async () => ({
    kind: "authenticated" as const,
    operator: { role },
    sessionToken: "server-token",
  });
}

function request(method: string, body?: unknown, origin = ORIGIN) {
  return new Request(`${ORIGIN}/api/clients/client-1/retention-policy`, {
    method,
    headers: { origin, host: "dashboard.example.test", "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

type Sent = { token: string; method: string; clientId: string; body: unknown };

function upstream(response: Response) {
  const sent: Sent[] = [];
  return {
    sent,
    send: async (token: string, method: string, clientId: string, body?: unknown) => {
      sent.push({ token, method, clientId, body });
      return response;
    },
  };
}

test("a PUT forwards only known categories with the version check", async () => {
  const api = upstream(Response.json(policyPayload({ version: 4 })));
  const response = await handleRetentionPolicyRequest(
    request("PUT", { expected_version: 3, telemetry_days: 60, alert_days: null }),
    "client-1",
    { getSession: session(), send: api.send },
  );
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.policy.version, 4);
  assert.deepEqual(api.sent, [{
    token: "server-token",
    method: "PUT",
    clientId: "client-1",
    body: { expected_version: 3, telemetry_days: 60, alert_days: null },
  }]);
});

test("unknown fields, or a missing version, are refused before reaching the server", async () => {
  for (const body of [
    { expected_version: 3, audit_days: 1 },
    { telemetry_days: 30 },
    { expected_version: "3" },
    { expected_version: 3, telemetry_days: "30" },
  ]) {
    const api = upstream(Response.json(policyPayload()));
    const response = await handleRetentionPolicyRequest(request("PUT", body), "client-1", {
      getSession: session(), send: api.send,
    });
    assert.equal(response.status, 400, JSON.stringify(body));
    assert.equal(api.sent.length, 0);
  }
  const api = upstream(Response.json(policyPayload()));
  const response = await handleRetentionPolicyRequest(
    request("DELETE", { expected_version: 3, telemetry_days: 1 }),
    "client-1",
    { getSession: session(), send: api.send },
  );
  assert.equal(response.status, 400);
  assert.equal(api.sent.length, 0);
});

test("a cross-origin write, or one below the global admin role, never reaches the server", async () => {
  const api = upstream(Response.json(policyPayload()));
  const crossOrigin = await handleRetentionPolicyRequest(
    request("PUT", { expected_version: 3 }, "https://evil.example.test"),
    "client-1",
    { getSession: session(), send: api.send },
  );
  assert.equal(crossOrigin.status, 403);
  const operator = await handleRetentionPolicyRequest(
    request("DELETE", { expected_version: 3 }),
    "client-1",
    { getSession: session("operator"), send: api.send },
  );
  assert.equal(operator.status, 403);
  assert.equal(api.sent.length, 0);
});

test("a read-only member may still reload the policy", async () => {
  const api = upstream(Response.json(policyPayload({ can_edit: false })));
  const response = await handleRetentionPolicyRequest(request("GET"), "client-1", {
    getSession: session("readonly"), send: api.send,
  });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).policy.canEdit, false);
  assert.equal(api.sent[0].method, "GET");
});

test("server error codes and the offending category pass through", async () => {
  const cases: [number, Record<string, string>][] = [
    [409, { code: "retention_policy_conflict" }],
    [422, { code: "retention_below_minimum", category: "alert_days" }],
    [403, { code: "step_up_required", message: "Re-authenticate." }],
    [404, { code: "client_not_found" }],
  ];
  for (const [status, detail] of cases) {
    const api = upstream(Response.json({ detail }, { status }));
    const response = await handleRetentionPolicyRequest(
      request("PUT", { expected_version: 3 }),
      "client-1",
      { getSession: session(), send: api.send },
    );
    assert.equal(response.status, status);
    const body = await response.json();
    assert.equal(body.code, detail.code);
    assert.equal(body.category, detail.category ?? null);
    assert.equal(typeof body.error, "string");
  }
});

test("a plain role refusal becomes a stable message, and a bad session is 401", async () => {
  const api = upstream(Response.json({ detail: "Requires client role 'client_admin'" }, { status: 403 }));
  const refused = await handleRetentionPolicyRequest(
    request("PUT", { expected_version: 3 }),
    "client-1",
    { getSession: session(), send: api.send },
  );
  assert.equal(refused.status, 403);
  assert.match((await refused.json()).error, /cannot change retention/);
  const anonymous = await handleRetentionPolicyRequest(request("GET"), "client-1", {
    getSession: async () => ({ kind: "anonymous" as const }), send: api.send,
  });
  assert.equal(anonymous.status, 401);
});
