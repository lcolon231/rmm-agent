// SPDX-License-Identifier: AGPL-3.0-only
// The server-only NodeLink API clients (issue #281), driven through the real
// `nodelinkApiRequest` against a scripted global fetch.

import assert from "node:assert/strict";
import test from "node:test";

import * as adminSessions from "@/lib/nodelink-admin-sessions";
import { assistantRequest } from "@/lib/nodelink-assistant";
import { NodelinkApiError, nodelinkApiRequest, nodelinkApiRequestRaw } from "@/lib/nodelink-api";
import {
  NodelinkAuthenticationError,
  NodelinkSecondFactorRequired,
  authenticateOperator,
  currentOperator,
  revokeOperatorTokens,
} from "@/lib/nodelink-auth";
import * as mfa from "@/lib/nodelink-mfa";
import { mfaCookieName } from "@/lib/mfa-core";
import { getClientNavigation } from "@/lib/client-navigation";
import { getEndpointList } from "@/lib/endpoint-list";
import { setRequestCookies } from "./support/next-headers-stub.ts";
import { fakeApi, jsonResponse, type RecordedCall } from "./support/fake-api.ts";

const operator = { id: "op-1", email: "ops@example.test", role: "admin", disabled: false };
const pathOf = (call: RecordedCall) => new URL(call.url).pathname + new URL(call.url).search;

// --------------------------------------------------------------------------- //
// nodelink-api
// --------------------------------------------------------------------------- //
test("API requests go to the configured base with the bearer and a timeout", async (t) => {
  const calls = fakeApi(t, () => jsonResponse(200, { ok: true }));
  assert.deepEqual(await nodelinkApiRequest("/api/v1/x", { method: "GET", sessionToken: "tok" }), { ok: true });
  assert.equal(calls[0].url, "http://127.0.0.1:8000/api/v1/x");
  assert.equal(calls[0].headers.get("Authorization"), "Bearer tok");
  assert.ok(calls[0].signal);

  const raw = await nodelinkApiRequestRaw("/api/v1/zip", { method: "POST", sessionToken: "tok" });
  assert.ok(raw instanceof Response);
  assert.equal(calls[1].method, "POST");
});

test("a non-2xx becomes a NodelinkApiError carrying the machine code", async (t) => {
  fakeApi(t, () => jsonResponse(403, { detail: { code: "step_up_required" } }));
  await assert.rejects(
    nodelinkApiRequest("/api/v1/x", { method: "GET", sessionToken: "tok" }),
    (error) => error instanceof NodelinkApiError && error.status === 403 && error.code === "step_up_required",
  );
});

// --------------------------------------------------------------------------- //
// nodelink-auth
// --------------------------------------------------------------------------- //
test("a password login fetches the operator with the new token", async (t) => {
  const calls = fakeApi(t, (call) =>
    pathOf(call) === "/api/v1/auth/login"
      ? jsonResponse(200, { access_token: "fresh", token_type: "bearer" })
      : jsonResponse(200, operator));
  const result = await authenticateOperator({ email: "ops@example.test", password: "pw" });
  assert.deepEqual(result, { operator, sessionToken: "fresh" });
  assert.equal(calls[0].method, "POST");
  assert.deepEqual(JSON.parse(calls[0].body!), { email: "ops@example.test", password: "pw" });
  assert.equal(calls[0].headers.get("Authorization"), null);
  assert.equal(pathOf(calls[1]), "/api/v1/auth/me");
  assert.equal(calls[1].headers.get("Authorization"), "Bearer fresh");
});

test("a refused login surfaces the upstream status", async (t) => {
  fakeApi(t, () => jsonResponse(401, { detail: "bad" }));
  await assert.rejects(
    authenticateOperator({ email: "a@b.test", password: "x" }),
    (error) => error instanceof NodelinkAuthenticationError && error.status === 401,
  );
});

test("an MFA challenge is thrown as its own type, never returned as a session", async (t) => {
  const body = { access_token: "restricted", token_type: "bearer", mfa_required: true };
  const calls = fakeApi(t, () => jsonResponse(200, body));
  await assert.rejects(
    authenticateOperator({ email: "a@b.test", password: "x" }),
    (error) => error instanceof NodelinkSecondFactorRequired && (error.body as typeof body).access_token === "restricted",
  );
  assert.equal(calls.length, 1, "the restricted token is never used to load an operator");
});

for (const [label, body] of [
  ["a missing token", { access_token: null, token_type: "bearer" }],
  ["a non-bearer token type", { access_token: "t", token_type: "mac" }],
] as const) {
  test(`a login success with ${label} is a 502, not a session`, async (t) => {
    fakeApi(t, () => jsonResponse(200, body));
    await assert.rejects(
      authenticateOperator({ email: "a@b.test", password: "x" }),
      (error) => error instanceof NodelinkAuthenticationError && error.status === 502,
    );
  });
}

test("currentOperator and revokeOperatorTokens hit their endpoints", async (t) => {
  const calls = fakeApi(t, (call) => (call.method === "POST" ? jsonResponse(204) : jsonResponse(200, operator)));
  assert.deepEqual(await currentOperator("tok"), operator);
  assert.equal(await revokeOperatorTokens("tok"), undefined);
  assert.deepEqual(calls.map((c) => [c.method, pathOf(c)]), [
    ["GET", "/api/v1/auth/me"],
    ["POST", "/api/v1/auth/revoke-tokens"],
  ]);
});

// --------------------------------------------------------------------------- //
// nodelink-mfa and nodelink-admin-sessions: { status, code, body } shaping
// --------------------------------------------------------------------------- //
type Shaped = { status: number; code?: string | null; body?: unknown };
type HelperCase = [string, (token: string) => Promise<Shaped>, string, string, unknown?];

const helperCases: HelperCase[] = [
  ["fetchLoginOptions", (k) => mfa.fetchLoginOptions(k), "POST", "/api/v1/auth/mfa/login/options"],
  ["verifyLoginAssertion", (k) => mfa.verifyLoginAssertion(k, { a: 1 }), "POST", "/api/v1/auth/mfa/login/verify", { a: 1 }],
  ["verifyRecoveryCode", (k) => mfa.verifyRecoveryCode(k, { code: "c" }), "POST", "/api/v1/auth/mfa/login/recovery-code", { code: "c" }],
  ["sendLoginEmailCode", (k) => mfa.sendLoginEmailCode(k), "POST", "/api/v1/auth/mfa/login/email/send"],
  ["verifyLoginEmailCode", (k) => mfa.verifyLoginEmailCode(k, { code: "1" }), "POST", "/api/v1/auth/mfa/login/email/verify", { code: "1" }],
  ["startEmailEnrollment", (k) => mfa.startEmailEnrollment(k), "POST", "/api/v1/auth/mfa/email/enrollment/start"],
  ["verifyEmailEnrollment", (k) => mfa.verifyEmailEnrollment(k, { code: "2" }), "POST", "/api/v1/auth/mfa/email/enrollment/verify", { code: "2" }],
  ["removeEmailFactor", (k) => mfa.removeEmailFactor(k, { reason: "r" }), "POST", "/api/v1/auth/mfa/email", { reason: "r" }],
  ["fetchRegistrationOptions", (k) => mfa.fetchRegistrationOptions(k), "POST", "/api/v1/auth/mfa/credentials/options"],
  ["renameCredential", (k) => mfa.renameCredential(k, "a/b", { name: "n" }), "PUT", "/api/v1/auth/mfa/credentials/a%2Fb", { name: "n" }],
  ["revokeCredential", (k) => mfa.revokeCredential(k, "a/b", { reason: "r" }), "POST", "/api/v1/auth/mfa/credentials/a%2Fb/revoke", { reason: "r" }],
  ["generateRecoveryCodes", (k) => mfa.generateRecoveryCodes(k), "POST", "/api/v1/auth/mfa/recovery-codes"],
  ["fetchStepUpOptions", (k) => mfa.fetchStepUpOptions(k), "POST", "/api/v1/auth/mfa/step-up/options"],
  ["verifyStepUp", (k) => mfa.verifyStepUp(k, { s: 1 }), "POST", "/api/v1/auth/mfa/step-up/verify", { s: 1 }],
  ["listOwnSessions", (k) => adminSessions.listOwnSessions(k), "GET", "/api/v1/auth/sessions?include_ended=true"],
  ["revokeOwnSession", (k) => adminSessions.revokeOwnSession(k, "s/1", { r: 1 }), "POST", "/api/v1/auth/sessions/s%2F1/revoke", { r: 1 }],
  ["revokeOtherOwnSessions", (k) => adminSessions.revokeOtherOwnSessions(k, { r: 1 }), "POST", "/api/v1/auth/sessions/revoke-others", { r: 1 }],
  ["listBreakGlassAccounts", (k) => adminSessions.listBreakGlassAccounts(k), "GET", "/api/v1/auth/break-glass"],
  ["rotateBreakGlassCredential", (k) => adminSessions.rotateBreakGlassCredential(k, "b/1", { r: 1 }), "POST", "/api/v1/auth/break-glass/b%2F1/rotate", { r: 1 }],
  ["setBreakGlassDisabled", (k) => adminSessions.setBreakGlassDisabled(k, "b/1", { d: true }), "PUT", "/api/v1/auth/break-glass/b%2F1/disabled", { d: true }],
  ["reviewBreakGlassActivation", (k) => adminSessions.reviewBreakGlassActivation(k, "a/1", { ok: 1 }), "POST", "/api/v1/auth/break-glass/activations/a%2F1/review", { ok: 1 }],
];

test("each MFA and session helper calls its endpoint with the token and JSON body", async (t) => {
  const calls = fakeApi(t, () => jsonResponse(200, { echoed: true }));
  for (const [name, invoke, method, path, body] of helperCases) {
    const result = await invoke("tok");
    const call = calls.at(-1)!;
    assert.deepEqual(result, { status: 200, body: { echoed: true } }, name);
    assert.equal(call.method, method, name);
    assert.equal(pathOf(call), path, name);
    assert.equal(call.headers.get("Authorization"), "Bearer tok", name);
    if (body === undefined) {
      assert.equal(call.body, null, `${name} sends no body`);
      assert.equal(call.headers.get("Content-Type"), null, name);
    } else {
      assert.deepEqual(JSON.parse(call.body!), body, name);
      assert.equal(call.headers.get("Content-Type"), "application/json", name);
    }
  }
});

test("creation endpoints report 201 on success", async (t) => {
  fakeApi(t, () => jsonResponse(201, { id: "new" }));
  assert.deepEqual(await mfa.registerCredential("tok", { x: 1 }), { status: 201, body: { id: "new" } });
  assert.deepEqual(await adminSessions.createBreakGlassAccount("tok", { x: 1 }), { status: 201, body: { id: "new" } });
});

test("break-glass activation is unauthenticated upstream and sends only a sentinel bearer", async (t) => {
  const calls = fakeApi(t, () => jsonResponse(200, { access_token: "x" }));
  assert.equal((await adminSessions.activateBreakGlass({ username: "u" })).status, 200);
  assert.equal(pathOf(calls[0]), "/api/v1/auth/break-glass/activate");
  assert.equal(calls[0].headers.get("Authorization"), "Bearer break-glass-activation");
});

test("an upstream refusal is returned as status and code rather than thrown", async (t) => {
  fakeApi(t, () => jsonResponse(429, { detail: { code: "rate_limited" } }));
  assert.deepEqual(await mfa.verifyStepUp("tok", {}), { status: 429, code: "rate_limited" });
  assert.deepEqual(await adminSessions.activateBreakGlass({}), { status: 429, code: "rate_limited" });
});

test("a transport failure is reported as 503 with no code", async (t) => {
  fakeApi(t, () => {
    throw new TypeError("fetch failed");
  });
  assert.deepEqual(await mfa.fetchLoginOptions("tok"), { status: 503, code: null });
  assert.deepEqual(await adminSessions.listOwnSessions("tok"), { status: 503, code: null });
});

test("page read helpers return data, or null when the API cannot answer", async (t) => {
  let fail = false;
  const calls = fakeApi(t, () => (fail ? jsonResponse(500) : jsonResponse(200, { read: true })));
  const reads: Array<[(token: string) => Promise<unknown>, string]> = [
    [mfa.fetchMfaStatus, "/api/v1/auth/mfa/status"],
    [adminSessions.fetchOwnSessions, "/api/v1/auth/sessions?include_ended=true"],
    [adminSessions.fetchBreakGlassAccounts, "/api/v1/auth/break-glass"],
    [adminSessions.fetchBreakGlassStatus, "/api/v1/auth/break-glass/status"],
    [adminSessions.fetchBreakGlassActivations, "/api/v1/auth/break-glass/activations"],
  ];
  for (const [read, path] of reads) {
    assert.deepEqual(await read("tok"), { read: true }, path);
    assert.equal(calls.at(-1)!.method, "GET");
    assert.equal(pathOf(calls.at(-1)!), path);
  }
  fail = true;
  for (const [read, path] of reads) {
    assert.equal(await read("tok"), null, path);
  }
});

test("the restricted MFA token is read from its own cookie", async () => {
  setRequestCookies({ [mfaCookieName()]: "restricted" });
  assert.equal(await mfa.readMfaCookie(), "restricted");
  setRequestCookies({});
  assert.equal(await mfa.readMfaCookie(), undefined);
});

// --------------------------------------------------------------------------- //
// Assistant, navigation and endpoint list
// --------------------------------------------------------------------------- //
test("assistant requests forward method and body with a long timeout", async (t) => {
  const calls = fakeApi(t, () => jsonResponse(200, { reply: "hi" }));
  assert.deepEqual(await assistantRequest("/api/v1/assistant/chat", "tok", "POST", "{\"q\":1}"), { reply: "hi" });
  assert.equal(calls[0].method, "POST");
  assert.equal(calls[0].body, "{\"q\":1}");
  assert.equal(calls[0].headers.get("Content-Type"), "application/json");
  await assistantRequest("/api/v1/assistant/history", "tok");
  assert.equal(calls[1].method, "GET");
});

test("client navigation is read from its endpoint", async (t) => {
  const data = { items: [], truncated: false };
  const calls = fakeApi(t, () => jsonResponse(200, data));
  assert.deepEqual(await getClientNavigation("tok"), data);
  assert.equal(pathOf(calls[0]), "/api/v1/clients/navigation");
});

test("the endpoint list query has stable defaults and only the filters given", async (t) => {
  const calls = fakeApi(t, () => jsonResponse(200, { items: [], page: 1, page_size: 25, total: 0 }));
  await getEndpointList("tok");
  assert.deepEqual(Object.fromEntries(new URL(calls[0].url).searchParams), {
    page: "1",
    page_size: "25",
    sort: "last_seen",
    direction: "desc",
  });

  await getEndpointList("tok", {
    clientId: "c1",
    direction: "asc",
    page: 3,
    search: "web & db",
    siteId: "s1",
    sort: "hostname",
    status: "offline",
  });
  assert.deepEqual(Object.fromEntries(new URL(calls[1].url).searchParams), {
    page: "3",
    page_size: "25",
    sort: "hostname",
    direction: "asc",
    client_id: "c1",
    site_id: "s1",
    status: "offline",
    search: "web & db",
  });
});
