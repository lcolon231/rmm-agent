// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  handleBreakGlassActivations,
  handleHealth,
  handleLogin,
  handleLogout,
  handleMfaStatus,
  type LoginAttempt,
} from "../src/lib/auth-route-core.ts";
import { sessionCookieName } from "../src/lib/dashboard-auth-core.ts";
import { mfaCookieName } from "../src/lib/mfa-core.ts";
import {
  SENTINEL,
  bffContract,
  dashboardOrigin,
  request,
  revokedSession,
  sessionFor,
  sessionToken,
  throwingSession,
  unavailableSession,
  upstream,
} from "./bff-contract.ts";

const mfaStatus = {
  enforcement: "optional",
  enrollment_required: false,
  enrolled: true,
  credential_count: 1,
  recovery_codes_remaining: 8,
  step_up_satisfied: false,
  session_methods: ["pwd"],
  credentials: [{ id: "cred-1", name: "YubiKey", algorithm: -7, aaguid: "x", transports: null, attestation_format: "none", backup_eligible: false, backup_state: false, created_at: "2026-10-01T00:00:00Z", last_used_at: null, public_key: SENTINEL }],
  totp_seed: SENTINEL,
};
const activation = {
  id: "act-1",
  account_id: "bg-1",
  session_id: null,
  activated_at: "2026-10-21T12:00:00Z",
  source_ip: "203.0.113.5",
  user_agent: null,
  reason: "IdP outage",
  reviewed_at: null,
  reviewed_by_email: null,
  review_note: null,
  credential_hash: SENTINEL,
};

bffContract([
  {
    name: "mfa status",
    minRole: "readonly",
    mutation: false,
    upstreamResult: mfaStatus,
    invoke: ({ getSession, call }) => handleMfaStatus(request("/api/auth/mfa/status"), { fetchMfaStatus: call, getSession }),
  },
  {
    name: "break-glass activations",
    minRole: "admin",
    mutation: false,
    upstreamResult: [activation],
    invoke: ({ getSession, call }) =>
      handleBreakGlassActivations(request("/api/auth/break-glass/activations"), {
        fetchBreakGlassActivations: call,
        getSession,
      }),
  },
]);

test("mfa status and activations report an unusable upstream answer as 503", async () => {
  const status = await handleMfaStatus(request("/x"), { fetchMfaStatus: async () => null, getSession: sessionFor("readonly") });
  assert.equal(status.status, 503);
  const activations = await handleBreakGlassActivations(request("/x"), {
    fetchBreakGlassActivations: async () => ({ not: "a list" }),
    getSession: sessionFor("admin"),
  });
  assert.equal(activations.status, 503);
});

function logoutRequest(origin: string | null = dashboardOrigin) {
  return request("/api/auth/logout", "POST", undefined, origin);
}

function clearsSessionCookie(cookies: Array<{ name: string; value: string; options: Record<string, unknown> }>) {
  return cookies.some((cookie) => cookie.name === sessionCookieName() && cookie.value === "" && cookie.options.maxAge === 0);
}

test("logout revokes a live session and clears the cookie", async () => {
  const revoke = upstream(undefined);
  const result = await handleLogout(logoutRequest(), { getSession: sessionFor("readonly"), revokeOperatorTokens: revoke.fn });
  assert.equal(result.response.status, 200);
  assert.deepEqual(revoke.calls, [[sessionToken]]);
  assert.ok(clearsSessionCookie(result.cookies));
});

test("logout never forwards a revoked or unverifiable cookie but still clears it", async () => {
  for (const [getSession, status] of [[revokedSession, 200], [unavailableSession, 503], [throwingSession, 503]] as const) {
    const revoke = upstream(undefined);
    const result = await handleLogout(logoutRequest(), { getSession, revokeOperatorTokens: revoke.fn });
    assert.equal(result.response.status, status);
    assert.equal(revoke.calls.length, 0);
    assert.ok(clearsSessionCookie(result.cookies));
  }
});

test("logout reports a failed revocation while still clearing the cookie", async () => {
  const result = await handleLogout(logoutRequest(), {
    getSession: sessionFor("admin"),
    revokeOperatorTokens: async () => { throw new Error("down"); },
  });
  assert.equal(result.response.status, 503);
  assert.ok(clearsSessionCookie(result.cookies));
});

test("logout refuses a cross-origin request without touching the session", async () => {
  let read = false;
  const result = await handleLogout(logoutRequest("https://attacker.example.test"), {
    getSession: async () => { read = true; return sessionFor("admin")(); },
    revokeOperatorTokens: async () => undefined,
  });
  assert.equal(result.response.status, 403);
  assert.equal(read, false);
  assert.deepEqual(result.cookies, []);
});

const credentials = { email: "tech@example.com", password: "correct horse battery" };
const operator = { id: "op-1", email: "tech@example.com", role: "operator" as const, disabled: false };

function loginJson(body: unknown = credentials, origin: string | null = dashboardOrigin) {
  return request("/api/auth/login", "POST", body, origin);
}

function loginForm(origin = dashboardOrigin) {
  return new Request(`${dashboardOrigin}/api/auth/login`, {
    body: new URLSearchParams(credentials),
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: origin },
    method: "POST",
  });
}

test("login sets the session cookie and returns only the operator's public fields", async () => {
  const result = await handleLogin(loginJson(), {
    authenticate: async () => ({ kind: "authenticated", operator: { ...operator, password_hash: SENTINEL } as typeof operator, sessionToken }),
  });
  assert.equal(result.response.status, 200);
  const text = await result.response.text();
  assert.ok(!text.includes(SENTINEL));
  assert.ok(!text.includes(sessionToken), "the token travels only in the cookie");
  assert.deepEqual(JSON.parse(text), { operator });
  assert.deepEqual(result.cookies.map((cookie) => [cookie.name, cookie.value]), [[sessionCookieName(), sessionToken]]);
});

test("a form login redirects home on success and back to /login on failure", async () => {
  const ok = await handleLogin(loginForm(), { authenticate: async () => ({ kind: "authenticated", operator, sessionToken }) });
  assert.equal(ok.response.status, 303);
  assert.equal(ok.response.headers.get("location"), `${dashboardOrigin}/`);

  const denied = await handleLogin(loginForm(), { authenticate: async () => ({ kind: "rejected", status: 401 }) });
  assert.equal(denied.response.status, 303);
  assert.equal(denied.response.headers.get("location"), `${dashboardOrigin}/login?error=invalid-credentials`);
  assert.deepEqual(denied.cookies, []);
});

test("login refuses cross-origin and invalid submissions before authenticating", async () => {
  for (const req of [loginJson(credentials, "https://attacker.example.test"), loginJson({ email: "nope" }), loginJson("{bad")]) {
    const double = upstream<LoginAttempt>({ kind: "authenticated", operator, sessionToken });
    const result = await handleLogin(req, { authenticate: double.fn as never });
    assert.ok(result.response.status === 403 || result.response.status === 400);
    assert.equal(double.calls.length, 0);
    assert.deepEqual(result.cookies, []);
  }
});

test("login maps rejections to fixed codes", async () => {
  for (const [upstreamStatus, status] of [[401, 401], [429, 429], [500, 503], [403, 503]]) {
    const result = await handleLogin(loginJson(), { authenticate: async () => ({ kind: "rejected", status: upstreamStatus }) });
    assert.equal(result.response.status, status);
  }
  const transport = await handleLogin(loginJson(), { authenticate: async () => { throw new TypeError("fetch failed"); } });
  assert.equal(transport.response.status, 503);
});

test("a second-factor login stores the restricted token and clears any old session", async () => {
  const body = { mfa_required: true, mfa_token: "restricted-token", mfa_methods: ["webauthn", "bogus"], mfa_enrollment_required: false };
  const json = await handleLogin(loginJson(), { authenticate: async () => ({ kind: "second-factor", body }) });
  assert.equal(json.response.status, 200);
  assert.deepEqual(await json.response.json(), { mfa_required: true, mfa_enrollment_required: false, mfa_methods: ["webauthn"] });
  assert.ok(json.cookies.some((cookie) => cookie.name === mfaCookieName() && cookie.value === "restricted-token"));
  assert.ok(clearsSessionCookie(json.cookies));

  const form = await handleLogin(loginForm(), { authenticate: async () => ({ kind: "second-factor", body }) });
  assert.equal(form.response.status, 303);
  assert.equal(form.response.headers.get("location"), `${dashboardOrigin}/login/mfa?methods=webauthn`);

  const malformed = await handleLogin(loginJson(), { authenticate: async () => ({ kind: "second-factor", body: { mfa_required: true } }) });
  assert.equal(malformed.response.status, 503);
  assert.deepEqual(malformed.cookies, []);
});

test("health reports one bit and never upstream detail", async () => {
  const ok = await handleHealth({ checkHealth: async () => "ok" });
  assert.deepEqual([ok.status, await ok.json()], [200, { status: "ok" }]);
  for (const checkHealth of [async () => "degraded" as const, async (): Promise<"ok"> => { throw new Error(SENTINEL); }]) {
    const response = await handleHealth({ checkHealth });
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { status: "degraded" });
  }
});
