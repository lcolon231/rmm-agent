// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";
import { handleAlertAction } from "../src/lib/alert-action-route-core.ts";

const alert = {
  id: "alert-1", agent_id: "agent-1", policy_id: "policy-1",
  policy_revision_id: "revision-1", check_key: "cpu", state: "acknowledged",
  last_result_status: "warning", occurrence_count: 1, total_occurrence_count: 1,
  generation: 1, first_opened_at: "2026-08-01T10:00:00Z",
  opened_at: "2026-08-01T10:00:00Z", last_observed_at: "2026-08-01T10:00:00Z",
  resolved_at: null, last_evaluated_at: "2026-08-01T10:00:00Z",
  last_result_id: "result-1", last_value: 90, resolution_reason: null,
  suppression_window_id: null, suppressed_until: null,
  assigned_to_operator_id: null, assigned_to_email: null,
  acknowledged_at: "2026-08-01T10:01:00Z", acknowledged_by: "tech@example.test",
  version: 3, created_at: "2026-08-01T10:00:00Z", updated_at: "2026-08-01T10:01:00Z",
  events: [], observations: [],
};

function request(body: unknown, origin = "https://dashboard.test") {
  return new Request("https://dashboard.test/api/alerts/alert-1/comments", {
    method: "POST", headers: { "Content-Type": "application/json", Origin: origin },
    body: JSON.stringify(body),
  });
}

test("route rejects cross-origin and read-only alert mutations", async () => {
  const dependencies = {
    getSession: async () => ({ kind: "authenticated" as const, operator: { role: "readonly" as const }, sessionToken: "server-secret" }),
    performAction: async () => alert,
  };
  assert.equal((await handleAlertAction(request({}, "https://evil.test"), "alert-1", "comments", dependencies)).status, 403);
  assert.equal((await handleAlertAction(request({}), "alert-1", "comments", dependencies)).status, 403);
});

test("route validates, forwards server session, and returns a minimal alert", async () => {
  let receivedToken = "";
  const response = await handleAlertAction(
    request({ request_id: "request-12345678", expected_version: 2, comment: "Investigating" }),
    "alert-1", "comments",
    {
      getSession: async () => ({ kind: "authenticated" as const, operator: { role: "operator" as const }, sessionToken: "server-secret" }),
      performAction: async (token) => { receivedToken = token; return { ...alert, access_token: "must-not-leak" }; },
    },
  );
  assert.equal(response.status, 200);
  assert.equal(receivedToken, "server-secret");
  const body = await response.json();
  assert.equal(body.alert.version, 3);
  assert.doesNotMatch(JSON.stringify(body), /server-secret|must-not-leak|access_token/);
});

test("version conflicts return refresh guidance", async () => {
  const error = Object.assign(new Error("conflict"), { status: 409, code: "alert_version_conflict" });
  const response = await handleAlertAction(
    request({ request_id: "request-12345678", expected_version: 2, comment: "Investigating" }),
    "alert-1", "comments",
    {
      getSession: async () => ({ kind: "authenticated" as const, operator: { role: "operator" as const }, sessionToken: "token" }),
      performAction: async () => { throw error; },
    },
  );
  assert.equal(response.status, 409);
  assert.match((await response.json()).error, /changed.*refresh/i);
});
