// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";

import { handleApprovalAction } from "../src/lib/approval-route-core.ts";

const DETAIL = {
  id: "req-1",
  agent_id: "agent-1",
  client_id: "client-1",
  site_id: "site-1",
  kind: "powershell",
  status: "approved",
  payload_sha256: "a".repeat(64),
  policy_id: "policy-1",
  required_approvals: 2,
  approvals_recorded: 2,
  requested_by_email: "req@example.test",
  requested_by_operator_id: "op-req",
  reason: "Spooler wedged, INC-4711",
  created_at: "2026-09-02T10:00:00Z",
  expires_at: "2026-09-02T11:00:00Z",
  decided_at: "2026-09-02T10:06:00Z",
  consumed_at: null,
  payload_keys: ["script"],
  decisions: [],
  closed_at: null,
  closed_by_email: null,
  closed_reason: null,
  consumed_command_id: null,
};

const REASON = "Change window confirmed for INC-4711";

function request(
  body: unknown,
  { origin = "https://dashboard.test" }: { origin?: string | null } = {},
) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (origin !== null) headers.origin = origin;
  return new Request("https://dashboard.test/api/approval-requests/req-1/approve", {
    body: JSON.stringify(body),
    headers,
    method: "POST",
  });
}

function session(role: "readonly" | "operator" | "admin" = "operator") {
  return async () =>
    ({ kind: "authenticated", operator: { role }, sessionToken: "token" }) as const;
}

function upstreamError(status: number, code?: string) {
  return async () => {
    throw Object.assign(new Error("upstream"), { status, code });
  };
}

test("a valid approval reaches the service and returns the request", async () => {
  let seen: unknown = null;
  const response = await handleApprovalAction(request({ reason: REASON }), "req-1", "approve", {
    getSession: session(),
    performAction: async (token, requestId, action, reason) => {
      seen = { token, requestId, action, reason };
      return DETAIL;
    },
  });
  assert.equal(response.status, 200);
  assert.deepEqual(seen, {
    token: "token",
    requestId: "req-1",
    action: "approve",
    reason: REASON,
  });
  assert.equal(response.headers.get("Cache-Control"), "no-store");
  const body = (await response.json()) as { request: { id: string } };
  assert.equal(body.request.id, "req-1");
});

test("a cross-origin decision is refused before any upstream call", async () => {
  let called = false;
  const response = await handleApprovalAction(
    request({ reason: REASON }, { origin: "https://evil.test" }),
    "req-1",
    "approve",
    {
      getSession: session(),
      performAction: async () => {
        called = true;
        return DETAIL;
      },
    },
  );
  assert.equal(response.status, 403);
  assert.equal(called, false);
});

test("a readonly role cannot decide", async () => {
  let called = false;
  const response = await handleApprovalAction(request({ reason: REASON }), "req-1", "approve", {
    getSession: session("readonly"),
    performAction: async () => {
      called = true;
      return DETAIL;
    },
  });
  assert.equal(response.status, 403);
  assert.equal(called, false);
});

test("an anonymous or unavailable session is refused", async () => {
  const anonymous = await handleApprovalAction(request({ reason: REASON }), "req-1", "approve", {
    getSession: async () => ({ kind: "anonymous" }) as const,
    performAction: async () => DETAIL,
  });
  assert.equal(anonymous.status, 401);

  const unavailable = await handleApprovalAction(request({ reason: REASON }), "req-1", "approve", {
    getSession: async () => {
      throw new Error("down");
    },
    performAction: async () => DETAIL,
  });
  assert.equal(unavailable.status, 503);
});

test("the reason is re-validated here, not only in the browser", async () => {
  let called = false;
  for (const body of [{}, { reason: "short" }, { reason: "x".repeat(600) }, null]) {
    const response = await handleApprovalAction(request(body), "req-1", "approve", {
      getSession: session(),
      performAction: async () => {
        called = true;
        return DETAIL;
      },
    });
    assert.equal(response.status, 400);
  }
  assert.equal(called, false);
});

test("self-approval is reported in the reviewer's own terms", async () => {
  const response = await handleApprovalAction(request({ reason: REASON }), "req-1", "approve", {
    getSession: session(),
    performAction: upstreamError(403, "approval_self_not_permitted"),
  });
  assert.equal(response.status, 403);
  const body = (await response.json()) as { error: string };
  assert.match(body.error, /you raised this request/i);
});

test("an ineligible approver is told why, without leaking policy detail", async () => {
  const response = await handleApprovalAction(request({ reason: REASON }), "req-1", "approve", {
    getSession: session(),
    performAction: upstreamError(403, "approver_script_permission_missing"),
  });
  const body = (await response.json()) as { error: string };
  assert.match(body.error, /not permitted to run yourself/i);
});

test("state and transport failures map to distinct statuses", async () => {
  const expired = await handleApprovalAction(request({ reason: REASON }), "req-1", "approve", {
    getSession: session(),
    performAction: upstreamError(409, "approval_request_expired"),
  });
  assert.equal(expired.status, 409);
  assert.match(((await expired.json()) as { error: string }).error, /expired/i);

  const missing = await handleApprovalAction(request({ reason: REASON }), "req-1", "approve", {
    getSession: session(),
    performAction: upstreamError(404),
  });
  assert.equal(missing.status, 404);

  const down = await handleApprovalAction(request({ reason: REASON }), "req-1", "approve", {
    getSession: session(),
    performAction: upstreamError(500),
  });
  assert.equal(down.status, 503);
});

test("an invalid service response is not passed through to the browser", async () => {
  const response = await handleApprovalAction(request({ reason: REASON }), "req-1", "reject", {
    getSession: session(),
    performAction: async () => ({ id: "req-1" }),
  });
  assert.equal(response.status, 502);
});
