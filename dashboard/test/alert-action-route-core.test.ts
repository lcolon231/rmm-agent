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

// --------------------------------------------------------------------------- //
// Coverage extension: session, role, validation, and upstream mapping
// --------------------------------------------------------------------------- //
type AlertSession =
  | { kind: "anonymous" } | { kind: "unavailable" }
  | { kind: "authenticated"; operator: { role: "readonly" | "operator" | "admin" }; sessionToken: string };
const validAction = { request_id: "request-12345678", expected_version: 2, comment: "Investigating" };
const alertActions = ["acknowledge", "assign", "comments", "resolve"] as const;

for (const action of alertActions) {
  test(`alert ${action}: anonymous, unavailable, and throwing sessions never reach the API`, async () => {
    const sessions: Array<[number, () => Promise<AlertSession>]> = [
      [401, async () => ({ kind: "anonymous" })],
      [503, async () => ({ kind: "unavailable" })],
      [503, async () => { throw new Error("boom"); }],
    ];
    for (const [status, getSession] of sessions) {
      let calls = 0;
      const res = await handleAlertAction(request(validAction), "alert-1", action, {
        getSession, performAction: async () => { calls += 1; return alert; },
      });
      assert.equal(res.status, status);
      assert.equal(calls, 0);
    }
  });

  test(`alert ${action}: maps upstream failures without leaking detail`, async () => {
    const cases: Array<[Record<string, unknown>, number]> = [
      [{ status: 409, code: "alert_version_conflict" }, 409],
      [{ status: 409, code: "other" }, 409],
      [{ status: 404 }, 404], [{ status: 422 }, 422], [{ status: 401 }, 401],
      [{ status: 403 }, 403], [{ status: 500 }, 503], [{}, 503],
    ];
    for (const [fields, expected] of cases) {
      const res = await handleAlertAction(request(validAction), "alert-1", action, {
        getSession: async () => ({ kind: "authenticated", operator: { role: "operator" }, sessionToken: "server-secret" }),
        performAction: async () => { throw Object.assign(new Error("SENTINEL-leak"), fields); },
      });
      assert.equal(res.status, expected);
      assert.doesNotMatch(JSON.stringify(await res.json()), /SENTINEL|server-secret/);
    }
    for (const thrown of [null, "SENTINEL-string"]) {
      const res = await handleAlertAction(request(validAction), "alert-1", action, {
        getSession: async () => ({ kind: "authenticated", operator: { role: "admin" }, sessionToken: "t" }),
        performAction: async () => { throw thrown; },
      });
      assert.equal(res.status, 503);
    }
  });
}

test("alert comment and resolve actions require a non-empty comment; others do not", async () => {
  const deps = {
    getSession: async (): Promise<AlertSession> => ({ kind: "authenticated", operator: { role: "operator" }, sessionToken: "t" }),
    performAction: async () => alert,
  };
  const noComment = { request_id: "request-12345678", expected_version: 2 };
  for (const action of ["comments", "resolve"] as const) {
    assert.equal((await handleAlertAction(request(noComment), "alert-1", action, deps)).status, 400);
    assert.equal((await handleAlertAction(request({ ...noComment, comment: "   " }), "alert-1", action, deps)).status, 400);
  }
  for (const action of ["acknowledge", "assign"] as const) {
    assert.equal((await handleAlertAction(request(noComment), "alert-1", action, deps)).status, 200);
  }
});

test("alert actions reject malformed bodies before the API", async () => {
  let calls = 0;
  const deps = {
    getSession: async (): Promise<AlertSession> => ({ kind: "authenticated", operator: { role: "operator" }, sessionToken: "t" }),
    performAction: async () => { calls += 1; return alert; },
  };
  for (const body of [
    null, [], "x", {}, { ...validAction, request_id: "short" }, { ...validAction, expected_version: 0 },
    { ...validAction, expected_version: 1.5 }, { ...validAction, comment: 5 },
    { ...validAction, comment: "x".repeat(2001) }, { ...validAction, assigned_to_operator_id: 7 },
  ]) {
    assert.equal((await handleAlertAction(request(body), "alert-1", "comments", deps)).status, 400, JSON.stringify(body)?.slice(0, 60));
  }
  const raw = new Request("https://dashboard.test/x", { method: "POST", headers: { Origin: "https://dashboard.test" }, body: "{bad" });
  assert.equal((await handleAlertAction(raw, "alert-1", "comments", deps)).status, 400);
  assert.equal(calls, 0);
});

test("alert assignment forwards a trimmed comment and nullable assignee, and 502s on bad evidence", async () => {
  let input: unknown;
  const deps = {
    getSession: async (): Promise<AlertSession> => ({ kind: "authenticated", operator: { role: "admin" }, sessionToken: "t" }),
    performAction: async (_t: string, _id: string, _a: string, received: unknown) => { input = received; return alert; },
  };
  const ok = await handleAlertAction(
    request({ ...validAction, comment: "  hi  ", assigned_to_operator_id: null }), "alert-1", "assign", deps,
  );
  assert.equal(ok.status, 200);
  assert.deepEqual(input, { ...validAction, comment: "hi", assigned_to_operator_id: null });
  const bad = await handleAlertAction(request(validAction), "alert-1", "assign", {
    ...deps, performAction: async () => ({ junk: "SENTINEL" }),
  });
  assert.equal(bad.status, 502);
  assert.doesNotMatch(JSON.stringify(await bad.json()), /SENTINEL/);
});
