// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  base64UrlToBytes,
  ceremonyErrorCode,
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
  handleEmailFactorMutation,
  handleRegistrationOptions,
  handleRenameCredential,
  handleSendEmailCode,
  handleStepUpOptions,
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

test("a relying-party mismatch is reported as configuration, not as a dismissal", () => {
  // The regression this guards: the API and the dashboard on different domains
  // makes the browser raise SecurityError, which used to surface as "the prompt
  // was dismissed" and sent the reader looking at their security key instead of
  // at MFA_RP_ID.
  const securityError = Object.assign(new Error("rp id"), { name: "SecurityError" });
  assert.equal(ceremonyErrorCode(securityError), "relying-party-mismatch");
  const message = mfaErrorMessage("relying-party-mismatch") ?? "";
  assert.match(message, /MFA_RP_ID/);
  assert.match(message, /administrator/i);
  // It must not read as something the user did.
  assert.equal(/dismiss/i.test(message), false);
});

test("only a genuine refusal is reported as a dismissal", () => {
  for (const name of ["NotAllowedError", "AbortError"]) {
    assert.equal(ceremonyErrorCode(Object.assign(new Error(name), { name })), "cancelled");
  }
  // A non-DOMException, or anything unrecognised, degrades to the same.
  assert.equal(ceremonyErrorCode(new Error("boom")), "cancelled");
  assert.equal(ceremonyErrorCode(null), "cancelled");
  assert.equal(ceremonyErrorCode("nonsense"), "cancelled");
});

test("re-registering the same authenticator is named accurately", () => {
  const error = Object.assign(new Error("dup"), { name: "InvalidStateError" });
  assert.equal(ceremonyErrorCode(error), "already-registered");
  assert.match(mfaErrorMessage("already-registered") ?? "", /already registered/i);
});

test("an unsupported algorithm is reported as a browser limitation", () => {
  const error = Object.assign(new Error("alg"), { name: "NotSupportedError" });
  assert.equal(ceremonyErrorCode(error), "unsupported-browser");
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

// --------------------------------------------------------------------------- //
// Device rename, email factor, and step-up options (coverage extension)
// --------------------------------------------------------------------------- //
type UpstreamReply = { status: number; code?: string | null; body?: unknown };

function recorder(reply: UpstreamReply) {
  const calls: unknown[][] = [];
  const fn = async (...args: unknown[]) => {
    calls.push(args);
    return reply;
  };
  return { calls, fn };
}

type MfaHandlerCase = {
  name: string;
  /** True when the handler authorises with the session cookie. */
  usesSession: boolean;
  successStatus: number;
  path: string;
  body?: unknown;
  run: (
    req: Request,
    deps: {
      getSession: () => Promise<
        | { kind: "anonymous" }
        | { kind: "unavailable" }
        | { kind: "authenticated"; operator: { role: string }; sessionToken: string }
      >;
      getMfaToken: () => Promise<string | undefined>;
    },
    upstream: (...args: unknown[]) => Promise<UpstreamReply>,
  ) => ReturnType<typeof handleRenameCredential>;
};

const mfaCases: MfaHandlerCase[] = [
  {
    name: "rename", usesSession: true, successStatus: 200, path: "/api/auth/mfa/credentials/c1",
    body: { name: "Office key" },
    run: (req, deps, upstream) => handleRenameCredential(req, "c1", { ...deps, rename: upstream }),
  },
  {
    name: "send email code (session)", usesSession: true, successStatus: 200,
    path: "/api/auth/mfa/email/enrol/send", body: {},
    run: (req, deps, upstream) => handleSendEmailCode(req, { ...deps, send: upstream, credential: "session" }),
  },
  {
    name: "send email code (mfa-token)", usesSession: false, successStatus: 200,
    path: "/api/auth/mfa/email/send", body: {},
    run: (req, deps, upstream) => handleSendEmailCode(req, { ...deps, send: upstream, credential: "mfa-token" }),
  },
  {
    name: "email factor confirm", usesSession: true, successStatus: 200,
    path: "/api/auth/mfa/email/confirm", body: { code: "123456" },
    run: (req, deps, upstream) => handleEmailFactorMutation(req, { ...deps, mutate: upstream, payload: "code" }),
  },
  {
    name: "email factor remove", usesSession: true, successStatus: 200,
    path: "/api/auth/mfa/email/remove", body: { reason: "No longer needed" },
    run: (req, deps, upstream) => handleEmailFactorMutation(req, { ...deps, mutate: upstream, payload: "reason" }),
  },
  {
    name: "step-up options", usesSession: true, successStatus: 200,
    path: "/api/auth/mfa/step-up/options",
    run: (req, deps, upstream) => handleStepUpOptions(req, { ...deps, fetchOptions: upstream }),
  },
];

function depsFor(c: MfaHandlerCase, state: "ok" | "anonymous" | "unavailable" | "throws") {
  const getSession = state === "ok"
    ? authenticatedSession
    : state === "anonymous"
      ? anonymousSession
      : state === "unavailable"
        ? unavailableSession
        : async (): Promise<never> => { throw new Error("boom"); };
  // The mfa-token credential must come from the cookie, never from the session.
  return c.usesSession
    ? { getSession, getMfaToken: withoutMfaToken }
    : { getSession: authenticatedSession, getMfaToken: state === "ok" ? withMfaToken : withoutMfaToken };
}

for (const c of mfaCases) {
  test(`mfa ${c.name}: refuses cross-origin without calling the API`, async () => {
    const up = recorder({ status: 200, body: {} });
    const result = await c.run(request(c.path, c.body, "https://evil.test"), depsFor(c, "ok"), up.fn);
    assert.equal(result.response.status, 403);
    assert.deepEqual(result.cookies, []);
    assert.equal(up.calls.length, 0);
  });

  test(`mfa ${c.name}: missing credential is rejected without calling the API`, async () => {
    const up = recorder({ status: 200, body: {} });
    const result = await c.run(request(c.path, c.body), depsFor(c, "anonymous"), up.fn);
    assert.equal(result.response.status, 401);
    assert.equal(up.calls.length, 0);
    if (c.usesSession) {
      const unavailable = await c.run(request(c.path, c.body), depsFor(c, "unavailable"), up.fn);
      assert.equal(unavailable.response.status, 503);
      const throws = await c.run(request(c.path, c.body), depsFor(c, "throws"), up.fn);
      assert.equal(throws.response.status, 503);
      assert.equal(up.calls.length, 0);
    }
  });

  test(`mfa ${c.name}: success forwards the right credential and never echoes it`, async () => {
    const up = recorder({ status: c.successStatus, body: { ok: true, state: "enabled" } });
    const result = await c.run(request(c.path, c.body), depsFor(c, "ok"), up.fn);
    assert.equal(result.response.status, c.successStatus);
    assert.equal(up.calls.length, 1);
    assert.equal(up.calls[0][0], c.usesSession ? sessionToken : mfaToken);
    assert.equal(result.response.headers.get("cache-control"), "no-store");
    assert.deepEqual(result.cookies, []);
    assert.doesNotMatch(JSON.stringify(await result.response.json()), /sentinel/);
  });

  test(`mfa ${c.name}: maps upstream statuses`, async () => {
    const expected: Array<[number, number]> = [
      [400, 400], [401, 401], [403, 403], [429, 429], [404, 503], [409, 503], [500, 503],
    ];
    for (const [status, mapped] of expected) {
      const up = recorder({ status, code: null, body: { detail: "upstream-sentinel-detail" } });
      const result = await c.run(request(c.path, c.body), depsFor(c, "ok"), up.fn);
      assert.equal(result.response.status, mapped);
      assert.doesNotMatch(JSON.stringify(await result.response.json()), /sentinel/);
    }
  });
}

test("mfa rename and email handlers refuse invalid bodies before the API", async () => {
  const rename = recorder({ status: 200 });
  const deps = { getSession: authenticatedSession, getMfaToken: withoutMfaToken };
  for (const body of [{}, { name: "" }, { name: "x".repeat(65) }, { name: 5 }, null]) {
    const result = await handleRenameCredential(request("/r", body), "c1", { ...deps, rename: rename.fn });
    assert.equal(result.response.status, 400);
  }
  const garbage = new Request(`${dashboardOrigin}/r`, {
    method: "POST", headers: { Origin: dashboardOrigin }, body: "not json",
  });
  assert.equal((await handleRenameCredential(garbage, "c1", { ...deps, rename: rename.fn })).response.status, 400);

  const mutate = recorder({ status: 200 });
  for (const body of [{}, { code: "12" }, { code: 123456 }, null]) {
    const result = await handleEmailFactorMutation(request("/e", body), { ...deps, mutate: mutate.fn, payload: "code" });
    assert.equal(result.response.status, 400);
  }
  for (const body of [{}, { reason: "no" }, { reason: 5 }]) {
    const result = await handleEmailFactorMutation(request("/e", body), { ...deps, mutate: mutate.fn, payload: "reason" });
    assert.equal(result.response.status, 400);
  }
  assert.equal(rename.calls.length + mutate.calls.length, 0);
});

test("mfa rename and email handlers forward only validated, trimmed payloads", async () => {
  const deps = { getSession: authenticatedSession, getMfaToken: withoutMfaToken };
  const rename = recorder({ status: 200, body: { id: "c1" } });
  await handleRenameCredential(request("/r", { name: "  Desk key  ", extra: "drop" }), "c1", { ...deps, rename: rename.fn });
  assert.deepEqual(rename.calls[0], [sessionToken, "c1", { name: "Desk key" }]);

  const code = recorder({ status: 200, body: {} });
  await handleEmailFactorMutation(request("/e", { code: "123 456", extra: "drop" }), { ...deps, mutate: code.fn, payload: "code" });
  assert.deepEqual(code.calls[0], [sessionToken, { code: "123456" }]);

  const reason = recorder({ status: 200, body: {} });
  await handleEmailFactorMutation(request("/e", { reason: "  Left the company ", code: "drop" }), { ...deps, mutate: reason.fn, payload: "reason" });
  assert.deepEqual(reason.calls[0], [sessionToken, { reason: "Left the company" }]);
});

test("an email-code login verifies a validated code and swaps cookies", async () => {
  const deps = { getSession: anonymousSession, getMfaToken: withMfaToken, kind: "email_code" as const };
  const bad = recorder({ status: 200, body: { access_token: upgradedToken } });
  const rejected = await handleLoginVerify(request("/v", { code: "abc" }), { ...deps, verify: bad.fn });
  assert.equal(rejected.response.status, 400);
  assert.equal(bad.calls.length, 0);

  const ok = recorder({ status: 200, body: { access_token: upgradedToken, refresh: "leak-sentinel" } });
  const result = await handleLoginVerify(request("/v", { code: "123 456" }), { ...deps, verify: ok.fn });
  assert.equal(result.response.status, 200);
  assert.deepEqual(ok.calls[0], [mfaToken, { code: "123456" }]);
  assert.equal(result.cookies[0].value, upgradedToken);
  assert.doesNotMatch(JSON.stringify(await result.response.json()), /sentinel/);
});

test("step-up options returns upstream options only on 200", async () => {
  const up = recorder({ status: 200, body: { publicKey: { challenge: "abc" } } });
  const result = await handleStepUpOptions(request("/s"), {
    getSession: authenticatedSession, getMfaToken: withoutMfaToken, fetchOptions: up.fn,
  });
  assert.deepEqual(await result.response.json(), { publicKey: { challenge: "abc" } });
});
