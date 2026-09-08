// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  adminSessionErrorCode,
  adminSessionErrorMessage,
  describeAuthMethods,
  describeClient,
  describeEndReason,
  inventoryWarning,
  orderSessions,
  sessionIsPasswordOnly,
  validateCredential,
  validateLabel,
  validateReason,
  type SessionRecord,
} from "../src/lib/admin-sessions-core.ts";
import {
  handleActivateBreakGlass,
  handleCreateBreakGlass,
  handleReviewActivation,
  handleRevokeOtherSessions,
  handleRevokeSession,
  handleRotateBreakGlass,
  handleSetBreakGlassDisabled,
  handleListSessions,
} from "../src/lib/admin-sessions-route-core.ts";

const dashboardOrigin = "https://dashboard.example.test";
const sessionToken = "session-token-sentinel";
const emergencyToken = "emergency-token-sentinel";

const authenticated = async () => ({
  kind: "authenticated" as const,
  operator: { role: "admin" },
  sessionToken,
});
const anonymous = async () => ({ kind: "anonymous" as const });
const unavailable = async () => ({ kind: "unavailable" as const });

function request(path: string, body?: unknown, origin = dashboardOrigin): Request {
  return new Request(`${dashboardOrigin}${path}`, {
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: {
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      Origin: origin,
    },
    method: "POST",
  });
}

function session(extra: Partial<SessionRecord> = {}): SessionRecord {
  return {
    id: "session-1",
    created_at: "2026-08-31T10:00:00Z",
    last_seen_at: "2026-08-31T11:00:00Z",
    absolute_expires_at: "2026-08-31T18:00:00Z",
    auth_methods: "pwd,webauthn",
    source_ip: "203.0.113.7",
    user_agent: "Mozilla/5.0 (Windows NT 10.0) Chrome/120",
    is_break_glass: false,
    ended_at: null,
    end_reason: null,
    is_current: false,
    ...extra,
  };
}

// --------------------------------------------------------------------------- //
// Presentation
// --------------------------------------------------------------------------- //
test("auth methods are rendered as something a person can act on", () => {
  assert.equal(describeAuthMethods("pwd,webauthn"), "Password + Security key");
  assert.equal(describeAuthMethods("pwd,recovery_code"), "Password + Recovery code");
  assert.equal(describeAuthMethods("break_glass"), "Break-glass");
  assert.equal(describeAuthMethods(""), "Unknown");
  // An unrecognised method is shown rather than dropped: hiding it would make
  // the inventory quietly incomplete.
  assert.equal(describeAuthMethods("pwd,future_method"), "Password + future_method");
});

test("a password-only session is identified so it can be called out", () => {
  assert.equal(sessionIsPasswordOnly(session({ auth_methods: "pwd" })), true);
  assert.equal(sessionIsPasswordOnly(session({ auth_methods: "pwd,webauthn" })), false);
  assert.equal(sessionIsPasswordOnly(session({ auth_methods: "" })), false);
});

test("the client description is coarse and never echoes the raw user agent", () => {
  assert.equal(
    describeClient("Mozilla/5.0 (Windows NT 10.0) Chrome/120"),
    "Chrome on Windows",
  );
  assert.equal(describeClient("Mozilla/5.0 (Macintosh) Firefox/121"), "Firefox on macOS");
  assert.equal(describeClient(null), "Unknown device");
  // Attacker-influenced text must not survive into the label.
  const hostile = describeClient("<script>alert(1)</script>");
  assert.equal(hostile.includes("<script>"), false);
});

test("end reasons are explained rather than shown as enum values", () => {
  assert.equal(describeEndReason("idle_timeout"), "Timed out after inactivity");
  assert.equal(describeEndReason("revoked_by_admin"), "Ended by an administrator");
  assert.equal(describeEndReason(null), undefined);
  assert.equal(describeEndReason("future_reason"), "future_reason");
});

test("the current session sorts first, then by most recently seen", () => {
  const ordered = orderSessions([
    session({ id: "old", last_seen_at: "2026-08-31T09:00:00Z" }),
    session({ id: "current", is_current: true, last_seen_at: "2026-08-30T09:00:00Z" }),
    session({ id: "recent", last_seen_at: "2026-08-31T12:00:00Z" }),
  ]);
  assert.deepEqual(ordered.map((row) => row.id), ["current", "recent", "old"]);
});

test("a live emergency session outranks every other warning", () => {
  assert.match(
    inventoryWarning([
      session({ auth_methods: "pwd" }),
      session({ id: "bg", is_break_glass: true, auth_methods: "break_glass" }),
    ]) ?? "",
    /break-glass/i,
  );
  assert.match(
    inventoryWarning([session({ auth_methods: "pwd" })]) ?? "",
    /password alone/i,
  );
  assert.equal(inventoryWarning([session()]), undefined);
  // An ended password-only session is history, not a live risk.
  assert.equal(
    inventoryWarning([session({ auth_methods: "pwd", ended_at: "2026-08-31T12:00:00Z" })]),
    undefined,
  );
});

// --------------------------------------------------------------------------- //
// Error mapping and validation
// --------------------------------------------------------------------------- //
test("upstream refusals map to actionable codes", () => {
  assert.equal(adminSessionErrorCode(403, "step_up_required"), "step-up-required");
  assert.equal(
    adminSessionErrorCode(403, "break_glass_cannot_provision"),
    "break-glass-cannot-provision",
  );
  assert.equal(adminSessionErrorCode(503, "break_glass_disabled"), "break-glass-disabled");
  assert.equal(adminSessionErrorCode(409, "activation_already_reviewed"), "already-reviewed");
  assert.equal(adminSessionErrorCode(409, "session_not_managed"), "session-not-managed");
  assert.equal(adminSessionErrorCode(404), "not-found");
  assert.equal(adminSessionErrorCode(429), "rate-limited");
  assert.equal(adminSessionErrorCode(500), "unavailable");
  assert.equal(adminSessionErrorMessage("not-a-code"), undefined);
});

test("free-text inputs are bounded before they are forwarded", () => {
  assert.equal(validateReason("  Lost the laptop  "), "Lost the laptop");
  assert.equal(validateReason("no"), null);
  assert.equal(validateReason("x".repeat(501)), null);
  assert.equal(validateLabel("Safe, London office"), "Safe, London office");
  assert.equal(validateLabel("ab"), null);
  assert.equal(validateCredential("nlbg_abcdefgh"), "nlbg_abcdefgh");
  assert.equal(validateCredential("short"), null);
  assert.equal(validateCredential(42), null);
});

// --------------------------------------------------------------------------- //
// Route handlers
// --------------------------------------------------------------------------- //
test("every mutating handler refuses cross-origin before spending a credential", async () => {
  const calls: string[] = [];
  const record = (name: string) => async () => {
    calls.push(name);
    return { status: 200 };
  };

  const results = await Promise.all([
    handleRevokeSession(
      request("/api/auth/sessions/s1/revoke", { reason: "Ending it" }, "https://evil.test"),
      "s1",
      { getSession: authenticated, revoke: record("revoke") },
    ),
    handleRevokeOtherSessions(
      request("/api/auth/sessions/revoke-others", { reason: "Ending them" }, "https://evil.test"),
      { getSession: authenticated, revokeOthers: record("revoke-others") },
    ),
    handleCreateBreakGlass(
      request("/api/auth/break-glass", { label: "Safe", reason: "Provisioning" }, "https://evil.test"),
      { create: record("create"), getSession: authenticated },
    ),
    handleActivateBreakGlass(
      request(
        "/api/auth/break-glass/activate",
        { credential: "nlbg_abcdefgh", reason: "Locked out" },
        "https://evil.test",
      ),
      { activate: record("activate") },
    ),
  ]);

  assert.deepEqual(calls, []);
  for (const result of results) {
    assert.equal(result.response.status, 403);
    assert.deepEqual(result.cookies, []);
  }
});

test("session listing requires a session and never leaks the token", async () => {
  let seen: string | null = null;
  const listed = await handleListSessions(request("/api/auth/sessions"), {
    getSession: authenticated,
    list: async (token) => {
      seen = token;
      return { status: 200, body: [session()] };
    },
  });
  assert.equal(seen, sessionToken);
  assert.equal(listed.response.status, 200);
  assert.equal((await listed.response.text()).includes(sessionToken), false);

  const anonymousResult = await handleListSessions(request("/api/auth/sessions"), {
    getSession: anonymous,
    list: async () => ({ status: 200 }),
  });
  assert.equal(anonymousResult.response.status, 401);
});

test("revocation forwards only a validated reason", async () => {
  let forwarded: unknown;
  const result = await handleRevokeSession(
    request("/api/auth/sessions/s1/revoke", { reason: "  Lost the laptop  " }),
    "s1",
    {
      getSession: authenticated,
      revoke: async (_token, id, body) => {
        assert.equal(id, "s1");
        forwarded = body;
        return { status: 200, body: { revoked: 1 } };
      },
    },
  );
  assert.deepEqual(forwarded, { reason: "Lost the laptop" });
  assert.equal(result.response.status, 200);

  let called = false;
  const refused = await handleRevokeSession(
    request("/api/auth/sessions/s1/revoke", { reason: "no" }),
    "s1",
    {
      getSession: authenticated,
      revoke: async () => {
        called = true;
        return { status: 200 };
      },
    },
  );
  assert.equal(called, false);
  assert.equal(refused.response.status, 400);
});

test("a step-up refusal is surfaced as needing re-authentication", async () => {
  const result = await handleRotateBreakGlass(
    request("/api/auth/break-glass/a1/rotate", { reason: "Seal broken" }),
    "a1",
    {
      getSession: authenticated,
      rotate: async () => ({ status: 403, code: "step_up_required" }),
    },
  );
  assert.equal(result.response.status, 403);
  const body = await result.response.json() as { code: string; error: string };
  assert.equal(body.code, "step-up-required");
  assert.match(body.error, /security key/i);
});

test("an emergency session is told plainly why it cannot provision", async () => {
  const result = await handleCreateBreakGlass(
    request("/api/auth/break-glass", { label: "Second envelope", reason: "Entrenching" }),
    {
      create: async () => ({ status: 403, code: "break_glass_cannot_provision" }),
      getSession: authenticated,
    },
  );
  assert.equal(result.response.status, 403);
  const body = await result.response.json() as { code: string; error: string };
  assert.equal(body.code, "break-glass-cannot-provision");
  assert.match(body.error, /emergency session cannot/i);
});

test("provisioning passes the one-time credential through without caching it", async () => {
  const credential = "nlbg_one-time-value";
  const result = await handleCreateBreakGlass(
    request("/api/auth/break-glass", { label: "Safe, London office", reason: "Provisioning" }),
    {
      create: async () => ({
        status: 201,
        body: { account: { id: "a1", label: "Safe, London office" }, credential },
      }),
      getSession: authenticated,
    },
  );
  assert.equal(result.response.status, 201);
  assert.equal(result.response.headers.get("Cache-Control"), "no-store");
  assert.equal((await result.response.text()).includes(credential), true);
});

test("disabling requires an explicit boolean, not a truthy value", async () => {
  for (const body of [
    { reason: "Decommissioning" },
    { disabled: "true", reason: "Decommissioning" },
    { disabled: 1, reason: "Decommissioning" },
  ]) {
    let called = false;
    const result = await handleSetBreakGlassDisabled(
      request("/api/auth/break-glass/a1/disabled", body),
      "a1",
      {
        getSession: authenticated,
        setDisabled: async () => {
          called = true;
          return { status: 200 };
        },
      },
    );
    assert.equal(called, false);
    assert.equal(result.response.status, 400);
  }
});

test("a second review is reported as already reviewed, not as a generic failure", async () => {
  const result = await handleReviewActivation(
    request("/api/auth/break-glass/activations/x/review", { note: "Checked with on-call" }),
    "x",
    {
      getSession: authenticated,
      review: async () => ({ status: 409, code: "activation_already_reviewed" }),
    },
  );
  assert.equal(result.response.status, 409);
  assert.equal((await result.response.json() as { code: string }).code, "already-reviewed");
});

// --------------------------------------------------------------------------- //
// Break-glass activation
// --------------------------------------------------------------------------- //
test("activation needs no session and sets one on success", async () => {
  let forwarded: unknown;
  const result = await handleActivateBreakGlass(
    request("/api/auth/break-glass/activate", {
      credential: "  nlbg_sealed-value  ",
      reason: "All administrators locked out",
    }),
    {
      activate: async (body) => {
        forwarded = body;
        return { status: 200, body: { access_token: emergencyToken } };
      },
    },
  );
  assert.deepEqual(forwarded, {
    credential: "nlbg_sealed-value",
    reason: "All administrators locked out",
  });
  assert.equal(result.response.status, 200);
  assert.equal(result.cookies.length, 1);
  assert.equal(result.cookies[0].value, emergencyToken);
  assert.equal(result.cookies[0].options.httpOnly, true);
  // The credential must not survive into the response the browser can read.
  assert.equal((await result.response.text()).includes("nlbg_"), false);
});

test("a refused activation sets no cookie and surfaces the rate limit", async () => {
  const refused = await handleActivateBreakGlass(
    request("/api/auth/break-glass/activate", {
      credential: "nlbg_wrong-value",
      reason: "Probing",
    }),
    { activate: async () => ({ status: 401 }) },
  );
  assert.equal(refused.response.status, 401);
  assert.deepEqual(refused.cookies, []);

  const limited = await handleActivateBreakGlass(
    request("/api/auth/break-glass/activate", {
      credential: "nlbg_wrong-value",
      reason: "Probing",
    }),
    { activate: async () => ({ status: 429 }) },
  );
  assert.equal(limited.response.status, 429);
  assert.equal((await limited.response.json() as { code: string }).code, "rate-limited");
});

test("activation refuses a missing reason before contacting the API", async () => {
  let called = false;
  const result = await handleActivateBreakGlass(
    request("/api/auth/break-glass/activate", { credential: "nlbg_sealed-value" }),
    {
      activate: async () => {
        called = true;
        return { status: 200, body: { access_token: emergencyToken } };
      },
    },
  );
  assert.equal(called, false);
  assert.equal(result.response.status, 400);
});

test("a success with no usable token never sets an empty session cookie", async () => {
  const result = await handleActivateBreakGlass(
    request("/api/auth/break-glass/activate", {
      credential: "nlbg_sealed-value",
      reason: "Locked out",
    }),
    { activate: async () => ({ status: 200, body: { access_token: null } }) },
  );
  assert.equal(result.response.status, 503);
  assert.deepEqual(result.cookies, []);
});

test("an unavailable session backend is reported as 503, not as a refusal", async () => {
  const result = await handleListSessions(request("/api/auth/sessions"), {
    getSession: unavailable,
    list: async () => ({ status: 200 }),
  });
  assert.equal(result.response.status, 503);
});
