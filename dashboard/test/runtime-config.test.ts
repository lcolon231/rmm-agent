// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  NodelinkApiError,
  extractNodelinkErrorCode,
  requestNodelinkApiRaw,
  requestNodelinkApi,
} from "../src/lib/nodelink-api-core.ts";
import { getNodelinkHealth } from "../src/lib/nodelink-health-core.ts";
import { getRuntimeConfig } from "../src/lib/runtime-config.ts";

test("uses the local API default outside production", () => {
  assert.deepEqual(getRuntimeConfig({ NODE_ENV: "development" }), {
    apiBaseUrl: "http://127.0.0.1:8000",
    apiTimeoutMs: 10_000,
  });
});

test("requires an explicit API URL in production", () => {
  assert.throws(
    () => getRuntimeConfig({ NODE_ENV: "production" }),
    /must be set in production/,
  );
});

test("allows a production HTTPS API URL", () => {
  assert.deepEqual(
    getRuntimeConfig({
      NODE_ENV: "production",
      NODELINK_API_BASE_URL: "https://rmm.example.test",
      NODELINK_API_TIMEOUT_MS: "15000",
    }),
    {
      apiBaseUrl: "https://rmm.example.test",
      apiTimeoutMs: 15_000,
    },
  );
});

test("rejects insecure non-loopback API URLs", () => {
  assert.throws(
    () => getRuntimeConfig({ NODELINK_API_BASE_URL: "http://rmm.example.test" }),
    /loopback/,
  );
});

test("rejects credentials and invalid timeout values", () => {
  assert.throws(
    () => getRuntimeConfig({ NODELINK_API_BASE_URL: "https://user:secret@example.test" }),
    /must not include credentials/,
  );
  assert.throws(
    () => getRuntimeConfig({ NODELINK_API_TIMEOUT_MS: "900" }),
    /1000 to 60000/,
  );
  assert.throws(
    () => getRuntimeConfig({ NODELINK_API_BASE_URL: "https://example.test/path" }),
    /must be an origin/,
  );
});

test("fails closed before calling the API without a session", async () => {
  let fetchCalled = false;

  await assert.rejects(
    () => requestNodelinkApi("/api/v1/agents", {
      sessionToken: "",
    }, {
      fetchImpl: async () => {
        fetchCalled = true;
        return new Response();
      },
      runtimeConfig: getRuntimeConfig({ NODE_ENV: "test" }),
    }),
    /server-managed operator session/,
  );

  assert.equal(fetchCalled, false);
});

test("forwards a server-managed token and disables request caching", async () => {
  let requestUrl = "";
  let requestInit: RequestInit | undefined;

  const result = await requestNodelinkApi<{ status: string }>("/api/v1/agents", {
    method: "GET",
    sessionToken: "session-token",
  }, {
    fetchImpl: async (input, init) => {
      requestUrl = String(input);
      requestInit = init;
      return Response.json({ status: "ok" });
    },
    runtimeConfig: getRuntimeConfig({ NODE_ENV: "test" }),
  });

  assert.deepEqual(result, { status: "ok" });
  assert.equal(requestUrl, "http://127.0.0.1:8000/api/v1/agents");
  assert.equal(new Headers(requestInit?.headers).get("Authorization"), "Bearer session-token");
  assert.equal(requestInit?.cache, "no-store");
});

test("redacts unsuccessful API responses behind a typed error", async () => {
  await assert.rejects(
    () => requestNodelinkApi("/api/v1/agents", {
      sessionToken: "session-token",
    }, {
      fetchImpl: async () => new Response("sensitive response body", { status: 403 }),
      runtimeConfig: getRuntimeConfig({ NODE_ENV: "test" }),
    }),
    (error: unknown) => error instanceof NodelinkApiError && error.status === 403,
  );
});

test("accepts no-content API responses without parsing a body", async () => {
  const result = await requestNodelinkApi<void>(
    "/api/v1/auth/operators/operator-1/revoke-tokens",
    { method: "POST", sessionToken: "session-token" },
    {
      fetchImpl: async () => new Response(null, { status: 204 }),
      runtimeConfig: getRuntimeConfig({ NODE_ENV: "test" }),
    },
  );
  assert.equal(result, undefined);
});

test("reports a degraded health state without exposing upstream failure details", async () => {
  const health = await getNodelinkHealth({
    fetchImpl: async () => {
      throw new Error("connection refused at internal-api.example.test");
    },
    runtimeConfig: getRuntimeConfig({ NODE_ENV: "test" }),
  });

  assert.equal(health, "degraded");
});

test("extractNodelinkErrorCode reads only a string detail.code", () => {
  assert.equal(extractNodelinkErrorCode({ detail: { code: "mfa_required" } }), "mfa_required");
  for (const body of [null, undefined, "x", 5, {}, { detail: null }, { detail: "x" }, { detail: {} }, { detail: { code: 7 } }]) {
    assert.equal(extractNodelinkErrorCode(body), null);
  }
});

test("typed errors carry the machine code but never the upstream body", async () => {
  await assert.rejects(
    () => requestNodelinkApi("/api/v1/agents", { sessionToken: "t" }, {
      fetchImpl: async () => Response.json({ detail: { code: "step_up_required", secret: "SENTINEL" } }, { status: 403 }),
      runtimeConfig: getRuntimeConfig({ NODE_ENV: "test" }),
    }),
    (error: unknown) => error instanceof NodelinkApiError && error.status === 403
      && error.code === "step_up_required" && !error.message.includes("SENTINEL"),
  );
  const plain = new NodelinkApiError(500);
  assert.equal(plain.code, null);
  assert.equal(plain.name, "NodelinkApiError");
});

test("requestNodelinkApi rejects relative paths before fetching", async () => {
  let called = false;
  await assert.rejects(
    () => requestNodelinkApi("api/v1/agents", { sessionToken: "t" }, {
      fetchImpl: async () => { called = true; return new Response(); },
      runtimeConfig: getRuntimeConfig({ NODE_ENV: "test" }),
    }),
    /must start with '\/'/,
  );
  assert.equal(called, false);
});

test("requestNodelinkApi honours a caller-supplied abort signal and merges headers", async () => {
  const controller = new AbortController();
  let init: RequestInit | undefined;
  await requestNodelinkApi("/api/v1/x", {
    sessionToken: "t", signal: controller.signal, headers: { "X-Trace": "1" },
  }, {
    fetchImpl: async (_input, received) => { init = received; return Response.json({}); },
    runtimeConfig: getRuntimeConfig({ NODE_ENV: "test" }),
  });
  assert.equal(init?.signal, controller.signal);
  assert.equal(new Headers(init?.headers).get("X-Trace"), "1");
  assert.equal(new Headers(init?.headers).get("Accept"), "application/json");
});

test("requestNodelinkApiRaw returns the response untouched and validates its inputs", async () => {
  const upstream = new Response("zip-bytes", { status: 418 });
  let init: RequestInit | undefined;
  let url = "";
  const config = getRuntimeConfig({ NODE_ENV: "test" });
  const response = await requestNodelinkApiRaw("/api/v1/installer", {
    sessionToken: "token", method: "POST", headers: { "X-Trace": "1" },
  }, {
    fetchImpl: async (input, received) => { url = String(input); init = received; return upstream; },
    runtimeConfig: config,
  });
  assert.equal(response, upstream);
  assert.equal(url, "http://127.0.0.1:8000/api/v1/installer");
  assert.equal(init?.cache, "no-store");
  assert.equal(init?.method, "POST");
  assert.equal(new Headers(init?.headers).get("Authorization"), "Bearer token");
  assert.equal(new Headers(init?.headers).get("X-Trace"), "1");
  assert.ok(init?.signal instanceof AbortSignal);

  const controller = new AbortController();
  await requestNodelinkApiRaw("/x", { sessionToken: "token", signal: controller.signal }, {
    fetchImpl: async (_input, received) => { init = received; return upstream; }, runtimeConfig: config,
  });
  assert.equal(init?.signal, controller.signal);

  let called = false;
  const deps = { fetchImpl: async () => { called = true; return upstream; }, runtimeConfig: config };
  await assert.rejects(() => requestNodelinkApiRaw("x", { sessionToken: "token" }, deps), /must start with '\/'/);
  await assert.rejects(() => requestNodelinkApiRaw("/x", { sessionToken: "  " }, deps), /server-managed operator session/);
  assert.equal(called, false);
});
