// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  base64UrlToBytes,
  bytesToBase64Url,
  mfaCookieName,
  mfaCookieOptions,
  clearedMfaCookieOptions,
  mfaErrorCodeForStatus,
  mfaErrorMessage,
  readLoginChallenge,
  toCreationOptions,
  toRequestOptions,
  validateDeviceName,
  validateRecoveryCode,
  validateRevokeReason,
} from "../src/lib/mfa-core.ts";
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

const dashboardOrigin = "https://dashboard.example.test";
const sessionToken = "session-token-sentinel";
const mfaToken = "mfa-token-sentinel";
const upgradedToken = "upgraded-session-token-sentinel";

const authenticatedSession = async () => ({
  kind: "authenticated" as const,
  operator: { role: "admin" },
  sessionToken,
});
const anonymousSession = async () => ({ kind: "anonymous" as const });
const unavailableSession = async () => ({ kind: "unavailable" as const });

const withMfaToken = async () => mfaToken;
const withoutMfaToken = async () => undefined;

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

const validAssertion = {
  credential_id: "Y3JlZGVudGlhbA",
  client_data_json: "Y2xpZW50RGF0YQ",
  authenticator_data: "YXV0aERhdGE",
  signature: "c2lnbmF0dXJl",
};

type CookieInstruction = { name: string; value: string; options: Record<string, unknown> };

function cookieNamed(result: { cookies: CookieInstruction[] }, name: string) {
  return result.cookies.find((cookie) => cookie.name === name);
}

// --------------------------------------------------------------------------- //
// Encoding
// --------------------------------------------------------------------------- //
test("base64url round-trips the byte values WebAuthn actually produces", () => {
  const bytes = new Uint8Array([0, 1, 62, 63, 127, 128, 254, 255]);
  const encoded = bytesToBase64Url(bytes);
  // Unpadded and URL-safe: the form the API speaks on every field.
  assert.equal(encoded.includes("="), false);
  assert.equal(/[+/]/.test(encoded), false);
  assert.deepEqual([...base64UrlToBytes(encoded)], [...bytes]);
});

test("base64url decoding handles every unpadded remainder length", () => {
  for (let length = 1; length <= 8; length += 1) {
    const bytes = new Uint8Array(length).fill(7);
    assert.deepEqual([...base64UrlToBytes(bytesToBase64Url(bytes))], [...bytes]);
  }
});

test("ceremony options are converted into the buffers the browser requires", () => {
  const creation = toCreationOptions({
    rp: { id: "rmm.example.test", name: "NodeLink" },
    user: { id: bytesToBase64Url(new Uint8Array([1, 2, 3])), name: "a@b.test", displayName: "a@b.test" },
    challenge: bytesToBase64Url(new Uint8Array([9, 9])),
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    timeout: 300000,
    excludeCredentials: [{ type: "public-key", id: "Y3JlZA", transports: ["usb"] }],
    authenticatorSelection: { userVerification: "required" },
    attestation: "none",
  });
  assert.deepEqual([...new Uint8Array(creation.challenge as ArrayBuffer)], [9, 9]);
  assert.deepEqual([...new Uint8Array(creation.user.id as ArrayBuffer)], [1, 2, 3]);
  assert.equal(creation.excludeCredentials?.length, 1);
  assert.deepEqual(creation.excludeCredentials?.[0].transports, ["usb"]);

  const assertion = toRequestOptions({
    challenge: bytesToBase64Url(new Uint8Array([4])),
    rpId: "rmm.example.test",
    timeout: 300000,
    // A descriptor with no transports must not produce an empty array, which
    // some authenticators treat differently from an absent one.
    allowCredentials: [{ type: "public-key", id: "Y3JlZA", transports: null }],
    userVerification: "required",
  });
  assert.equal(assertion.rpId, "rmm.example.test");
  assert.equal("transports" in (assertion.allowCredentials?.[0] ?? {}), false);
});

// --------------------------------------------------------------------------- //
// Login-response interpretation
// --------------------------------------------------------------------------- //
test("a completed login is not mistaken for a challenge", () => {
  assert.equal(readLoginChallenge({ access_token: "t", token_type: "bearer" }), null);
  assert.equal(readLoginChallenge(null), null);
  assert.equal(readLoginChallenge("nonsense"), null);
});

test("an mfa_required body with no usable token is not treated as a challenge", () => {
  // Falling through to the error path is safer than rendering a challenge page
  // that has no token to spend.
  assert.equal(readLoginChallenge({ mfa_required: true }), null);
  assert.equal(readLoginChallenge({ mfa_required: true, mfa_token: "" }), null);
  assert.equal(readLoginChallenge({ mfa_required: true, mfa_token: 42 }), null);
});

test("unknown challenge methods are dropped rather than passed through", () => {
  const challenge = readLoginChallenge({
    mfa_required: true,
    mfa_token: mfaToken,
    mfa_methods: ["webauthn", "sms", 7, "recovery_code"],
  });
  assert.deepEqual(challenge?.methods, ["webauthn", "recovery_code"]);
});

test("the login hand-off stores the restricted token and clears any stale session", () => {
  const outcome = loginOutcome({
    mfa_required: true,
    mfa_token: mfaToken,
    mfa_enrollment_required: true,
    mfa_methods: ["enrollment"],
  });
  assert.ok(outcome);
  const pending = cookieNamed(outcome, mfaCookieName());
  assert.equal(pending?.value, mfaToken);
  assert.equal(pending?.options.httpOnly, true);
  // A login that owes a second factor must not leave a previous session behind.
  const session = outcome.cookies.find((cookie) => cookie.name !== mfaCookieName());
  assert.equal(session?.value, "");
  assert.equal(session?.options.maxAge, 0);
});

test("the pending-MFA cookie is host-locked in production and expires on its own", () => {
  assert.equal(mfaCookieName("production"), "__Host-nodelink-mfa");
  assert.equal(mfaCookieOptions("production").secure, true);
  assert.equal(mfaCookieOptions("production").httpOnly, true);
  assert.ok(mfaCookieOptions("production").maxAge <= 10 * 60);
  assert.equal(clearedMfaCookieOptions("production").maxAge, 0);
});

// --------------------------------------------------------------------------- //
// Error mapping
// --------------------------------------------------------------------------- //
test("refusals collapse to one message so the dashboard adds no oracle", () => {
  // The server returns the same body for "no such credential" and "bad
  // signature"; restating a guess here would give that distinction back.
  assert.equal(mfaErrorCodeForStatus(401), "challenge-failed");
  assert.equal(mfaErrorCodeForStatus(400), "challenge-failed");
  assert.equal(
    mfaErrorMessage(mfaErrorCodeForStatus(401)),
    mfaErrorMessage(mfaErrorCodeForStatus(400)),
  );
  assert.equal(mfaErrorCodeForStatus(429), "rate-limited");
  assert.equal(mfaErrorCodeForStatus(403, "step_up_required"), "step-up-required");
  assert.equal(mfaErrorCodeForStatus(403, "mfa_verification_required"), "step-up-required");
  assert.equal(mfaErrorCodeForStatus(503, "mfa_disabled"), "mfa-disabled");
  assert.equal(mfaErrorCodeForStatus(500), "unavailable");
  assert.equal(mfaErrorMessage("not-a-code"), undefined);
});

// --------------------------------------------------------------------------- //
// Input validation
// --------------------------------------------------------------------------- //
test("device names, recovery codes, and reasons are bounded before forwarding", () => {
  assert.equal(validateDeviceName("  YubiKey 5C  "), "YubiKey 5C");
  assert.equal(validateDeviceName(""), null);
  assert.equal(validateDeviceName("   "), null);
  assert.equal(validateDeviceName("x".repeat(65)), null);
  assert.equal(validateDeviceName(42), null);

  assert.equal(validateRecoveryCode(" abcde-fghij "), "abcde-fghij");
  assert.equal(validateRecoveryCode(""), null);
  assert.equal(validateRecoveryCode("x".repeat(65)), null);

  assert.equal(validateRevokeReason("Lost the key"), "Lost the key");
  assert.equal(validateRevokeReason("no"), null);
  assert.equal(validateRevokeReason("x".repeat(501)), null);
});

// --------------------------------------------------------------------------- //
// Route handlers: origin and credential handling
// --------------------------------------------------------------------------- //
test("every mutating handler refuses cross-origin before spending a credential", async () => {
  const calls: string[] = [];
  const record = (name: string) => async () => {
    calls.push(name);
    return { status: 200 };
  };

  const results = await Promise.all([
    handleLoginOptions(request("/api/auth/mfa/login/options", undefined, "https://evil.test"), {
      fetchOptions: record("login-options"),
      getMfaToken: withMfaToken,
      getSession: anonymousSession,
    }),
    handleLoginVerify(
      request("/api/auth/mfa/login/verify", validAssertion, "https://evil.test"),
      {
        getMfaToken: withMfaToken,
        getSession: anonymousSession,
        kind: "webauthn",
        verify: record("login-verify"),
      },
    ),
    handleRegistrationOptions(
      request("/api/auth/mfa/credentials/options", undefined, "https://evil.test"),
      {
        fetchOptions: record("register-options"),
        getMfaToken: withMfaToken,
        getSession: authenticatedSession,
      },
    ),
    handleGenerateRecoveryCodes(
      request("/api/auth/mfa/recovery-codes", undefined, "https://evil.test"),
      {
        generate: record("recovery"),
        getMfaToken: withoutMfaToken,
        getSession: authenticatedSession,
      },
    ),
    handleStepUpVerify(
      request("/api/auth/mfa/step-up/verify", validAssertion, "https://evil.test"),
      { getMfaToken: withoutMfaToken, getSession: authenticatedSession, verify: record("step-up") },
    ),
  ]);

  assert.deepEqual(calls, []);
  for (const result of results) {
    assert.equal(result.response.status, 403);
    assert.deepEqual(result.cookies, []);
  }
});

test("login completion requires the restricted cookie, not a session", async () => {
  let called = false;
  const result = await handleLoginOptions(request("/api/auth/mfa/login/options"), {
    fetchOptions: async () => {
      called = true;
      return { status: 200 };
    },
    getMfaToken: withoutMfaToken,
    // An ordinary session is not a substitute: there is no half-login to finish.
    getSession: authenticatedSession,
  });
  assert.equal(called, false);
  assert.equal(result.response.status, 401);
});

test("a verified login swaps the restricted cookie for a session cookie", async () => {
  let forwarded: unknown;
  const result = await handleLoginVerify(
    request("/api/auth/mfa/login/verify", validAssertion),
    {
      getMfaToken: withMfaToken,
      getSession: anonymousSession,
      kind: "webauthn",
      verify: async (token, body) => {
        assert.equal(token, mfaToken);
        forwarded = body;
        return { status: 200, body: { access_token: upgradedToken } };
      },
    },
  );

  assert.deepEqual(forwarded, validAssertion);
  assert.equal(result.response.status, 200);
  const cleared = cookieNamed(result, mfaCookieName());
  assert.equal(cleared?.value, "");
  assert.equal(cleared?.options.maxAge, 0);
  const session = result.cookies.find((cookie) => cookie.name !== mfaCookieName());
  assert.equal(session?.value, upgradedToken);
  assert.equal(session?.options.httpOnly, true);
});

test("a refused login keeps the restricted cookie so a retry is possible", async () => {
  const result = await handleLoginVerify(
    request("/api/auth/mfa/login/verify", validAssertion),
    {
      getMfaToken: withMfaToken,
      getSession: anonymousSession,
      kind: "webauthn",
      verify: async () => ({ status: 401 }),
    },
  );
  assert.equal(result.response.status, 401);
  // Nothing cleared: the operator can touch their key again, or switch to a
  // recovery code, without re-entering their password.
  assert.deepEqual(result.cookies, []);
});

test("a rate-limited second factor is surfaced as 429, not flattened to a refusal", async () => {
  const result = await handleLoginVerify(
    request("/api/auth/mfa/login/verify", validAssertion),
    {
      getMfaToken: withMfaToken,
      getSession: anonymousSession,
      kind: "webauthn",
      verify: async () => ({ status: 429 }),
    },
  );
  assert.equal(result.response.status, 429);
  assert.equal(
    ((await result.response.json()) as { code: string }).code,
    "rate-limited",
  );
});

test("malformed ceremony payloads are refused before reaching the API", async () => {
  const cases: unknown[] = [
    undefined,
    {},
    { ...validAssertion, signature: 42 },
    { ...validAssertion, credential_id: "" },
    { ...validAssertion, client_data_json: "x".repeat(33 * 1024) },
  ];
  for (const body of cases) {
    let called = false;
    const result = await handleLoginVerify(
      request("/api/auth/mfa/login/verify", body),
      {
        getMfaToken: withMfaToken,
        getSession: anonymousSession,
        kind: "webauthn",
        verify: async () => {
          called = true;
          return { status: 200, body: { access_token: upgradedToken } };
        },
      },
    );
    assert.equal(called, false);
    assert.equal(result.response.status, 400);
  }
});

test("a recovery-code login forwards only a validated code", async () => {
  let forwarded: unknown;
  const result = await handleLoginVerify(
    request("/api/auth/mfa/login/recovery-code", { code: "  abcde-fghij  " }),
    {
      getMfaToken: withMfaToken,
      getSession: anonymousSession,
      kind: "recovery_code",
      verify: async (_token, body) => {
        forwarded = body;
        return { status: 200, body: { access_token: upgradedToken } };
      },
    },
  );
  assert.deepEqual(forwarded, { code: "abcde-fghij" });
  assert.equal(result.response.status, 200);
});

test("a successful login with no usable token is treated as unavailable", async () => {
  const result = await handleLoginVerify(
    request("/api/auth/mfa/login/verify", validAssertion),
    {
      getMfaToken: withMfaToken,
      getSession: anonymousSession,
      kind: "webauthn",
      verify: async () => ({ status: 200, body: { access_token: null } }),
    },
  );
  // Never set an empty session cookie and claim success.
  assert.equal(result.response.status, 503);
  assert.deepEqual(result.cookies, []);
});

// --------------------------------------------------------------------------- //
// Enrolment credential selection
// --------------------------------------------------------------------------- //
test("enrolment prefers a real session and falls back to the restricted token", async () => {
  const seen: string[] = [];
  const capture = async (token: string) => {
    seen.push(token);
    return { status: 200, body: {} };
  };

  await handleRegistrationOptions(request("/api/auth/mfa/credentials/options"), {
    fetchOptions: capture,
    getMfaToken: withMfaToken,
    getSession: authenticatedSession,
  });
  // Both credentials present: the session wins, matching the server, which
  // treats the restricted token as an enrolment credential only for someone
  // who has no other way in.
  assert.deepEqual(seen, [sessionToken]);

  await handleRegistrationOptions(request("/api/auth/mfa/credentials/options"), {
    fetchOptions: capture,
    getMfaToken: withMfaToken,
    getSession: anonymousSession,
  });
  assert.deepEqual(seen, [sessionToken, mfaToken]);
});

test("enrolment with neither credential forwards nothing", async () => {
  let called = false;
  const result = await handleRegistrationOptions(
    request("/api/auth/mfa/credentials/options"),
    {
      fetchOptions: async () => {
        called = true;
        return { status: 200 };
      },
      getMfaToken: withoutMfaToken,
      getSession: anonymousSession,
    },
  );
  assert.equal(called, false);
  assert.equal(result.response.status, 401);
});

test("registration forwards a validated name and bounded transports", async () => {
  let forwarded: Record<string, unknown> | undefined;
  const result = await handleRegisterCredential(
    request("/api/auth/mfa/credentials", {
      name: "  Work laptop  ",
      client_data_json: "Y2xpZW50",
      attestation_object: "YXR0",
      transports: ["usb", "nfc", 5, "ble", "a", "b", "c", "d", "e", "f"],
    }),
    {
      getMfaToken: withoutMfaToken,
      getSession: authenticatedSession,
      register: async (_token, body) => {
        forwarded = body as Record<string, unknown>;
        return { status: 201, body: { id: "credential-1" } };
      },
    },
  );
  assert.equal(result.response.status, 201);
  assert.equal(forwarded?.name, "Work laptop");
  assert.equal((forwarded?.transports as string[]).length, 8);
  assert.equal((forwarded?.transports as string[]).includes("5" as unknown as string), false);
});

test("registration refuses a missing name or ceremony field", async () => {
  for (const body of [
    { client_data_json: "a", attestation_object: "b" },
    { name: "ok", attestation_object: "b" },
    { name: "ok", client_data_json: "a" },
    { name: "", client_data_json: "a", attestation_object: "b" },
  ]) {
    let called = false;
    const result = await handleRegisterCredential(
      request("/api/auth/mfa/credentials", body),
      {
        getMfaToken: withoutMfaToken,
        getSession: authenticatedSession,
        register: async () => {
          called = true;
          return { status: 201 };
        },
      },
    );
    assert.equal(called, false);
    assert.equal(result.response.status, 400);
  }
});

// --------------------------------------------------------------------------- //
// Device management and step-up
// --------------------------------------------------------------------------- //
test("revocation requires a reason of substance", async () => {
  let called = false;
  const result = await handleRevokeCredential(
    request("/api/auth/mfa/credentials/x/revoke", { reason: "no" }),
    "credential-1",
    {
      getMfaToken: withoutMfaToken,
      getSession: authenticatedSession,
      revoke: async () => {
        called = true;
        return { status: 200 };
      },
    },
  );
  assert.equal(called, false);
  assert.equal(result.response.status, 400);
});

test("a step-up refusal is reported as needing re-authentication", async () => {
  const result = await handleRevokeCredential(
    request("/api/auth/mfa/credentials/x/revoke", { reason: "Retiring this key" }),
    "credential-1",
    {
      getMfaToken: withoutMfaToken,
      getSession: authenticatedSession,
      revoke: async () => ({ status: 403, code: "step_up_required" }),
    },
  );
  assert.equal(result.response.status, 403);
  const body = await result.response.json() as { code: string; error: string };
  assert.equal(body.code, "step-up-required");
  assert.match(body.error, /security key/i);
});

test("a completed step-up replaces the session cookie with the upgraded token", async () => {
  const result = await handleStepUpVerify(
    request("/api/auth/mfa/step-up/verify", validAssertion),
    {
      getMfaToken: withoutMfaToken,
      getSession: authenticatedSession,
      verify: async () => ({ status: 200, body: { access_token: upgradedToken } }),
    },
  );
  assert.equal(result.response.status, 200);
  assert.equal(result.cookies.length, 1);
  assert.equal(result.cookies[0].value, upgradedToken);
});

test("handlers report an unavailable session as 503 rather than a refusal", async () => {
  const result = await handleGenerateRecoveryCodes(
    request("/api/auth/mfa/recovery-codes"),
    {
      generate: async () => ({ status: 200 }),
      getMfaToken: withoutMfaToken,
      getSession: unavailableSession,
    },
  );
  assert.equal(result.response.status, 503);
});

test("every handler response forbids caching", async () => {
  const result = await handleGenerateRecoveryCodes(
    request("/api/auth/mfa/recovery-codes"),
    {
      // The plaintext codes pass through here exactly once and must not be
      // stored by any intermediary.
      generate: async () => ({ status: 200, body: { codes: ["A", "B"] } }),
      getMfaToken: withoutMfaToken,
      getSession: authenticatedSession,
    },
  );
  assert.equal(result.response.headers.get("Cache-Control"), "no-store");
});
