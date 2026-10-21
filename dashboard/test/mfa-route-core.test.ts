// SPDX-License-Identifier: AGPL-3.0-only
// Branches of the MFA route handlers that mfa-core.test.ts leaves open
// (issue #281): upstream failures after a valid request, missing credentials,
// and the enrolment-token fallbacks.

import assert from "node:assert/strict";
import test from "node:test";

import {
  handleGenerateRecoveryCodes,
  handleLoginOptions,
  handleLoginVerify,
  handleRegisterCredential,
  handleRegistrationOptions,
  handleRevokeCredential,
  handleStepUpVerify,
  loginOutcome,
} from "../src/lib/mfa-route-core.ts";

const origin = "https://dashboard.example.test";
const sessionToken = "session-token-sentinel";
const mfaToken = "mfa-token-sentinel";

const authenticated = async () => ({ kind: "authenticated" as const, operator: { role: "admin" }, sessionToken });
const anonymous = async () => ({ kind: "anonymous" as const });
const unavailable = async () => ({ kind: "unavailable" as const });
const broken = async (): Promise<never> => {
  throw new Error("session lookup failed");
};
const withMfa = async () => mfaToken;
const withoutMfa = async () => undefined;

function post(path: string, body?: unknown, from = origin): Request {
  return new Request(`${origin}${path}`, {
    method: "POST",
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: { Origin: from, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
  });
}

const assertion = { credential_id: "Y3JlZA", client_data_json: "Y2xpZW50", authenticator_data: "YXV0aA", signature: "c2ln" };
const registration = { name: "YubiKey 5", client_data_json: "Y2xpZW50", attestation_object: "YXR0ZXN0" };
const refused = async () => ({ status: 401, code: "mfa_verification_failed" });
const upstreamDown = async () => ({ status: 500, code: null });
const mustNotCall = async () => {
  throw new Error("must not reach the API");
};

async function statusAndCode(result: { response: Response }) {
  const body = await result.response.json();
  return [result.response.status, body.code];
}

// --------------------------------------------------------------------------- //
// Login completion
// --------------------------------------------------------------------------- //
test("login options pass the upstream body through on success", async () => {
  let seen = "";
  const result = await handleLoginOptions(post("/api/auth/mfa/login/options"), {
    fetchOptions: async (token) => {
      seen = token;
      return { status: 200, body: { challenge: "abc" } };
    },
    getMfaToken: withMfa,
    getSession: anonymous,
  });
  assert.equal(seen, mfaToken);
  assert.deepEqual(await result.response.json(), { challenge: "abc" });
  assert.deepEqual(result.cookies, []);
});

test("login options map an upstream refusal and an upstream fault differently", async () => {
  const deps = { getMfaToken: withMfa, getSession: anonymous };
  const rejected = await handleLoginOptions(post("/api/auth/mfa/login/options"), { ...deps, fetchOptions: refused });
  assert.equal(rejected.response.status, 401);
  const faulted = await handleLoginOptions(post("/api/auth/mfa/login/options"), { ...deps, fetchOptions: upstreamDown });
  assert.equal(faulted.response.status, 503);
});

test("login verification without the restricted cookie is a 401 before any parsing", async () => {
  const result = await handleLoginVerify(post("/api/auth/mfa/login/verify", assertion), {
    getMfaToken: withoutMfa,
    getSession: anonymous,
    kind: "webauthn",
    verify: mustNotCall,
  });
  assert.equal(result.response.status, 401);
});

test("a verified login whose body is not an object is unavailable, not a session", async () => {
  const result = await handleLoginVerify(post("/api/auth/mfa/login/verify", assertion), {
    getMfaToken: withMfa,
    getSession: anonymous,
    kind: "webauthn",
    verify: async () => ({ status: 200, body: "token-as-a-string" }),
  });
  assert.equal(result.response.status, 503);
  assert.deepEqual(result.cookies, []);
});

test("a login body that is not a challenge yields no MFA outcome", () => {
  assert.equal(loginOutcome({ access_token: "t", token_type: "bearer" }), null);
  assert.equal(loginOutcome(null), null);
});

// --------------------------------------------------------------------------- //
// Enrolment
// --------------------------------------------------------------------------- //
test("registration options surface an upstream refusal", async () => {
  const result = await handleRegistrationOptions(post("/api/auth/mfa/credentials/options"), {
    fetchOptions: async () => ({ status: 403, code: "step_up_required" }),
    getMfaToken: withoutMfa,
    getSession: authenticated,
  });
  assert.equal(result.response.status, 403);
});

test("registration refuses cross-origin before spending a credential", async () => {
  const result = await handleRegisterCredential(post("/api/auth/mfa/credentials", registration, "https://evil.test"), {
    getMfaToken: withMfa,
    getSession: authenticated,
    register: mustNotCall,
  });
  assert.equal(result.response.status, 403);
});

test("the enrolment credential falls back carefully when the session cannot be read", async () => {
  const cases: Array<[string, typeof authenticated | typeof broken | typeof unavailable | typeof anonymous, typeof withMfa | typeof withoutMfa, number]> = [
    // A lookup that throws is an outage: never fall through to the restricted token.
    ["session lookup throws", broken, withMfa, 503],
    // Unavailable with a pending login: the restricted token is still a valid enrolment credential.
    ["session unavailable, restricted token present", unavailable, withMfa, 201],
    ["session unavailable, no restricted token", unavailable, withoutMfa, 503],
    ["anonymous, no restricted token", anonymous, withoutMfa, 401],
  ];
  for (const [label, getSession, getMfaToken, expected] of cases) {
    const result = await handleRegisterCredential(post("/api/auth/mfa/credentials", registration), {
      getMfaToken,
      getSession,
      register: async (token) => {
        assert.equal(token, mfaToken, label);
        return { status: 201, body: { id: "cred" } };
      },
    });
    assert.equal(result.response.status, expected, label);
  }
});

test("registration forwards an oversize attestation to nobody", async () => {
  const result = await handleRegisterCredential(
    post("/api/auth/mfa/credentials", { ...registration, attestation_object: "x".repeat(64 * 1024 + 1) }),
    { getMfaToken: withoutMfa, getSession: authenticated, register: mustNotCall },
  );
  assert.equal(result.response.status, 400);
});

test("registration surfaces an upstream refusal instead of a 201", async () => {
  const result = await handleRegisterCredential(post("/api/auth/mfa/credentials", registration), {
    getMfaToken: withoutMfa,
    getSession: authenticated,
    register: async () => ({ status: 400, code: "mfa_attestation_invalid" }),
  });
  assert.equal(result.response.status, 400);
});

// --------------------------------------------------------------------------- //
// Device management, recovery codes, step-up
// --------------------------------------------------------------------------- //
test("revocation needs same origin and a session, then returns the upstream body", async () => {
  const body = { reason: "Lost on travel" };
  const crossOrigin = await handleRevokeCredential(post("/x", body, "https://evil.test"), "cred", {
    getMfaToken: withoutMfa, getSession: authenticated, revoke: mustNotCall,
  });
  assert.equal(crossOrigin.response.status, 403);

  const signedOut = await handleRevokeCredential(post("/x", body), "cred", {
    getMfaToken: withMfa, getSession: anonymous, revoke: mustNotCall,
  });
  assert.equal(signedOut.response.status, 401, "the restricted token cannot revoke devices");

  let forwarded: unknown;
  const ok = await handleRevokeCredential(post("/x", body), "cred", {
    getMfaToken: withoutMfa,
    getSession: authenticated,
    revoke: async (_token, id, payload) => {
      forwarded = [id, payload];
      return { status: 200, body: { revoked: true } };
    },
  });
  assert.deepEqual(forwarded, ["cred", { reason: "Lost on travel" }]);
  assert.deepEqual(await ok.response.json(), { revoked: true });
});

test("recovery-code generation surfaces a step-up refusal", async () => {
  const result = await handleGenerateRecoveryCodes(post("/api/auth/mfa/recovery-codes"), {
    generate: async () => ({ status: 403, code: "step_up_required" }),
    getMfaToken: withoutMfa,
    getSession: authenticated,
  });
  assert.deepEqual(await statusAndCode(result), [403, "step-up-required"]);
});

test("step-up verification refuses each way it can fail", async () => {
  const path = "/api/auth/mfa/step-up/verify";
  const signedOut = await handleStepUpVerify(post(path, assertion), { getMfaToken: withMfa, getSession: anonymous, verify: mustNotCall });
  assert.equal(signedOut.response.status, 401);

  const malformed = await handleStepUpVerify(post(path, { credential_id: "only" }), { getMfaToken: withoutMfa, getSession: authenticated, verify: mustNotCall });
  assert.equal(malformed.response.status, 400);

  const rejected = await handleStepUpVerify(post(path, assertion), { getMfaToken: withoutMfa, getSession: authenticated, verify: refused });
  assert.equal(rejected.response.status, 401);

  const tokenless = await handleStepUpVerify(post(path, assertion), {
    getMfaToken: withoutMfa,
    getSession: authenticated,
    verify: async () => ({ status: 200, body: { access_token: "" } }),
  });
  assert.equal(tokenless.response.status, 503);
  assert.deepEqual(tokenless.cookies, [], "the old session cookie is left in place");
});
