// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  NodelinkApiError,
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

test("reports a degraded health state without exposing upstream failure details", async () => {
  const health = await getNodelinkHealth({
    fetchImpl: async () => {
      throw new Error("connection refused at internal-api.example.test");
    },
    runtimeConfig: getRuntimeConfig({ NODE_ENV: "test" }),
  });

  assert.equal(health, "degraded");
});
