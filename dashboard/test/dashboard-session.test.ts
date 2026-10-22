// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import { resolveDashboardSession } from "../src/lib/dashboard-session-core.ts";
import { NodelinkApiError, requestNodelinkApi } from "../src/lib/nodelink-api-core.ts";
import type { DashboardOperator } from "../src/lib/dashboard-auth-core.ts";
import { getDashboardSession } from "@/lib/dashboard-session";
import { setRequestCookies } from "./support/next-headers-stub.ts";
import { fakeApi, jsonResponse } from "./support/fake-api.ts";

const operator: DashboardOperator = { id: "op-1", email: "ops@example.test", role: "operator", disabled: false };
const runtimeConfig = { apiBaseUrl: "https://api.example.test", apiTimeoutMs: 1_000 };

/** `/auth/me` through the real request helper, so status classification is the production path. */
function meVia(fetchImpl: typeof fetch) {
  return (sessionToken: string) =>
    requestNodelinkApi<DashboardOperator>("/api/v1/auth/me", { method: "GET", sessionToken }, { fetchImpl, runtimeConfig });
}

test("no session cookie is anonymous without calling the API", async () => {
  let called = false;
  const load = async () => {
    called = true;
    return operator;
  };
  assert.deepEqual(await resolveDashboardSession(undefined, load), { kind: "anonymous" });
  assert.deepEqual(await resolveDashboardSession("", load), { kind: "anonymous" });
  assert.equal(called, false);
});

const outcomes: Array<[string, typeof fetch, string]> = [
  ["a 401 (expired or revoked token)", async () => jsonResponse(401, { detail: "expired" }), "anonymous"],
  ["a 403 (disabled operator)", async () => jsonResponse(403, { detail: "disabled" }), "anonymous"],
  ["a 500", async () => jsonResponse(500, { detail: "boom" }), "unavailable"],
  ["a 503", async () => jsonResponse(503), "unavailable"],
  ["a transport error", async () => { throw new TypeError("fetch failed"); }, "unavailable"],
  ["a timeout", async () => { throw new DOMException("timed out", "TimeoutError"); }, "unavailable"],
];

for (const [label, fetchImpl, kind] of outcomes) {
  test(`${label} never yields an authenticated session`, async () => {
    const state = await resolveDashboardSession("token-sentinel", meVia(fetchImpl));
    assert.deepEqual(state, { kind });
  });
}

test("a 200 revalidation carries the operator and role through", async () => {
  let authorization: string | null = null;
  const state = await resolveDashboardSession("token-sentinel", meVia(async (_url, init) => {
    authorization = new Headers(init?.headers).get("Authorization");
    return jsonResponse(200, operator);
  }));
  assert.equal(authorization, "Bearer token-sentinel");
  assert.deepEqual(state, { kind: "authenticated", operator, sessionToken: "token-sentinel" });
  assert.equal(state.kind === "authenticated" && state.operator.role, "operator");
});

test("only a NodelinkApiError status can downgrade to anonymous", async () => {
  // A plain error that happens to carry a status is not an API verdict.
  const lookalike = Object.assign(new Error("odd"), { status: 401 });
  assert.deepEqual(await resolveDashboardSession("t", async () => { throw lookalike; }), { kind: "unavailable" });
  assert.deepEqual(await resolveDashboardSession("t", async () => { throw new NodelinkApiError(403); }), { kind: "anonymous" });
});

test("getDashboardSession reads the session cookie and asks /auth/me", async (t) => {
  const calls = fakeApi(t, () => jsonResponse(200, operator));
  setRequestCookies({ "nodelink-session": "cookie-token" });
  const state = await getDashboardSession();
  assert.deepEqual(state, { kind: "authenticated", operator, sessionToken: "cookie-token" });
  assert.equal(calls.length, 1);
  assert.equal(new URL(calls[0].url).pathname, "/api/v1/auth/me");
  assert.equal(calls[0].headers.get("Authorization"), "Bearer cookie-token");

  setRequestCookies({});
  assert.deepEqual(await getDashboardSession(), { kind: "anonymous" });
  assert.equal(calls.length, 1);
});
