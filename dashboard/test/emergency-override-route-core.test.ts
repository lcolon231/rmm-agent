// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";

import {
  handleOverrideAction,
  parseActivateInput,
  type OverrideRouteDependencies,
} from "../src/lib/emergency-override-route-core.ts";

const DETAIL = {
  id: "ovr-1",
  agent_id: "agent-1",
  client_id: "client-1",
  site_id: "site-1",
  kind: "powershell",
  status: "active",
  payload_sha256: "a".repeat(64),
  policy_id: "policy-1",
  required_approvals: 2,
  activated_by_email: "admin@example.test",
  activated_by_operator_id: "op-admin",
  justification: "Print server down for 40 users, INC-9001, approvers unreachable",
  created_at: "2026-10-21T09:55:00Z",
  expires_at: "2026-10-21T10:10:00Z",
  consumed_at: null,
  revoked_at: null,
  revoked_by_email: null,
  notified_at: "2026-10-21T09:55:01Z",
  notification_error: null,
  notified_recipient_count: 2,
  reviewed_at: null,
  reviewed_by_email: null,
  payload: { script: "Restart-Service -Name Spooler" },
  payload_keys: ["script"],
  revoke_reason: null,
  review_note: null,
  consumed_command_id: null,
};

const ACTIVATE_BODY = {
  agent_id: "agent-1",
  kind: "powershell",
  payload: { script: "Restart-Service -Name Spooler" },
  justification: DETAIL.justification,
  ttl_seconds: 900,
};

function request(
  body: unknown,
  { origin = "https://dashboard.test", path = "/api/emergency-overrides" }: { origin?: string | null; path?: string } = {},
) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (origin !== null) headers.origin = origin;
  return new Request(`https://dashboard.test${path}`, {
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    headers,
    method: "POST",
  });
}

function session(role: "readonly" | "operator" | "admin" = "admin") {
  return async () =>
    ({ kind: "authenticated", operator: { role }, sessionToken: "token" }) as const;
}

function upstreamError(status: number, code?: string) {
  return async () => {
    throw Object.assign(new Error("upstream"), { status, code });
  };
}

function deps(overrides: Partial<OverrideRouteDependencies> = {}): OverrideRouteDependencies {
  return {
    getSession: session(),
    activate: async () => DETAIL,
    revoke: async () => ({ ...DETAIL, status: "revoked", revoked_by_email: "admin@example.test" }),
    review: async () => ({ ...DETAIL, reviewed_at: "2026-10-21T10:30:00Z", reviewed_by_email: "other@example.test" }),
    run: async () => ({ ...DETAIL, status: "consumed", consumed_command_id: "cmd-1" }),
    ...overrides,
  };
}

test("parseActivateInput accepts a valid body and refuses drift", () => {
  assert.deepEqual(parseActivateInput(ACTIVATE_BODY), ACTIVATE_BODY);
  assert.deepEqual(parseActivateInput({ ...ACTIVATE_BODY, ttl_seconds: undefined, payload: undefined }), {
    agent_id: "agent-1",
    kind: "powershell",
    payload: {},
    justification: DETAIL.justification,
  });
  assert.equal(parseActivateInput({ ...ACTIVATE_BODY, kind: "queued" }), null);
  assert.equal(parseActivateInput({ ...ACTIVATE_BODY, justification: "urgent" }), null);
  assert.equal(parseActivateInput({ ...ACTIVATE_BODY, ttl_seconds: 7200 }), null);
  assert.equal(parseActivateInput({ ...ACTIVATE_BODY, payload: ["x"] }), null);
  assert.equal(parseActivateInput({ ...ACTIVATE_BODY, agent_id: "" }), null);
});

test("activation reaches the service with the validated input and returns 201", async () => {
  let seen: unknown = null;
  const response = await handleOverrideAction(request(ACTIVATE_BODY), "activate", null, deps({
    activate: async (_token, input) => {
      seen = input;
      return DETAIL;
    },
  }));
  assert.equal(response.status, 201);
  assert.deepEqual(seen, ACTIVATE_BODY);
  assert.deepEqual(await response.json(), { override: DETAIL });
});

test("cross-origin, anonymous, unavailable, and readonly callers are refused", async () => {
  assert.equal(
    (await handleOverrideAction(request(ACTIVATE_BODY, { origin: "https://evil.test" }), "activate", null, deps())).status,
    403,
  );
  assert.equal(
    (await handleOverrideAction(request(ACTIVATE_BODY), "activate", null, deps({ getSession: async () => ({ kind: "anonymous" }) }))).status,
    401,
  );
  assert.equal(
    (await handleOverrideAction(request(ACTIVATE_BODY), "activate", null, deps({ getSession: async () => ({ kind: "unavailable" }) }))).status,
    503,
  );
  assert.equal(
    (await handleOverrideAction(request(ACTIVATE_BODY), "activate", null, deps({ getSession: session("readonly") }))).status,
    403,
  );
});

test("a malformed activation never reaches the service", async () => {
  let called = false;
  const response = await handleOverrideAction(
    request({ ...ACTIVATE_BODY, justification: "no" }),
    "activate",
    null,
    deps({ activate: async () => { called = true; return DETAIL; } }),
  );
  assert.equal(response.status, 400);
  assert.equal(called, false);
});

test("service refusal codes become readable messages with the upstream status", async () => {
  const cases: Array<[number, string, string]> = [
    [409, "emergency_override_not_permitted", "does not allow emergency overrides"],
    [403, "emergency_override_role_insufficient", "tenant administrator"],
    [403, "step_up_required", "security key"],
    [429, "emergency_override_limit_reached", "maximum number"],
  ];
  for (const [status, code, fragment] of cases) {
    const response = await handleOverrideAction(
      request(ACTIVATE_BODY),
      "activate",
      null,
      deps({ activate: upstreamError(status, code) }),
    );
    assert.equal(response.status, status, code);
    const body = (await response.json()) as { error: string };
    assert.match(body.error, new RegExp(fragment), code);
  }
});

test("revoke and review validate their text and forward trimmed", async () => {
  let seenReason: string | null = null;
  const revoked = await handleOverrideAction(
    request({ reason: "  Approver is back online now  " }, { path: "/api/emergency-overrides/ovr-1/revoke" }),
    "revoke",
    "ovr-1",
    deps({ revoke: async (_t, _id, reason) => { seenReason = reason; return { ...DETAIL, status: "revoked" }; } }),
  );
  assert.equal(revoked.status, 200);
  assert.equal(seenReason, "Approver is back online now");

  const short = await handleOverrideAction(
    request({ note: "ok" }, { path: "/api/emergency-overrides/ovr-1/review" }),
    "review",
    "ovr-1",
    deps(),
  );
  assert.equal(short.status, 400);

  const selfReview = await handleOverrideAction(
    request({ note: "Checked the ticket, warranted" }, { path: "/api/emergency-overrides/ovr-1/review" }),
    "review",
    "ovr-1",
    deps({ review: upstreamError(403, "emergency_override_self_review_not_permitted") }),
  );
  assert.equal(selfReview.status, 403);
  assert.match(((await selfReview.json()) as { error: string }).error, /cannot review it/);
});

test("run takes no body and returns the consumed override", async () => {
  const response = await handleOverrideAction(
    request(undefined, { path: "/api/emergency-overrides/ovr-1/run" }),
    "run",
    "ovr-1",
    deps(),
  );
  assert.equal(response.status, 200);
  const body = (await response.json()) as { override: { status: string; consumed_command_id: string } };
  assert.equal(body.override.status, "consumed");
  assert.equal(body.override.consumed_command_id, "cmd-1");

  const replay = await handleOverrideAction(
    request(undefined, { path: "/api/emergency-overrides/ovr-1/run" }),
    "run",
    "ovr-1",
    deps({ run: upstreamError(409, "emergency_override_already_consumed") }),
  );
  assert.equal(replay.status, 409);
  assert.match(((await replay.json()) as { error: string }).error, /already been used/);
});

test("an invalid service response is a 502, never rendered", async () => {
  const response = await handleOverrideAction(
    request(ACTIVATE_BODY),
    "activate",
    null,
    deps({ activate: async () => ({ id: "ovr-1" }) }),
  );
  assert.equal(response.status, 502);
});
