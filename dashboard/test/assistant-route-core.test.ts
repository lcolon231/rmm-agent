// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";
import { assistantPath, handleAssistant } from "../src/lib/assistant-route-core.ts";

const id = "11111111-1111-4111-8111-111111111111";
const base = "https://dashboard.test";
const session = async () => ({ kind: "authenticated" as const, sessionToken: "server-only-token" });

test("assistant proxy accepts only the closed read-only API surface", () => {
  for (const parts of [["..", "commands"], ["conversations", "../secrets"], ["conversations", id, "commands"], ["https:", "evil.test"]]) {
    assert.equal(assistantPath(parts, "POST", new URL(base)), null);
  }
  assert.equal(assistantPath(["conversations"], "GET", new URL(`${base}?client_id=${id}&token=ignored`)), `/api/v1/assistant/conversations?client_id=${id}`);
  assert.equal(assistantPath(["conversations", id, "runs", id, "cancel"], "POST", new URL(base)), `/api/v1/assistant/conversations/${id}/runs/${id}/cancel`);
});

test("same-origin and authenticated operator session required before forwarding", async () => {
  let forwarded = false;
  const send = async () => { forwarded = true; };
  const foreign = await handleAssistant(new Request(base, { method: "POST", headers: { origin: "https://foreign.test" }, body: "{}" }), ["conversations"], { getSession: session, send });
  assert.equal(foreign.status, 403);
  const anonymous = await handleAssistant(new Request(base), ["status"], { getSession: async () => ({ kind: "anonymous" }), send });
  assert.equal(anonymous.status, 401);
  assert.equal(forwarded, false);
});

test("forwards only server session, disables caching, and does not echo upstream secrets", async () => {
  const response = await handleAssistant(new Request(base), ["status"], { getSession: session, send: async (path, token) => {
    assert.equal(path, "/api/v1/assistant/status"); assert.equal(token, "server-only-token");
    return { state: "available" };
  } });
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual(await response.json(), { state: "available" });
  const failed = await handleAssistant(new Request(base), ["status"], { getSession: session, send: async () => { throw new Error("secret-provider-body"); } });
  assert.equal(failed.status, 503);
  assert.ok(!(await failed.text()).includes("secret-provider-body"));
});

test("bounds chunked input before backend requests", async () => {
  let called = false;
  const result = await handleAssistant(new Request(base, { method: "POST", headers: { origin: base }, body: "x".repeat(20001) }), ["conversations"], {
    getSession: session, send: async () => { called = true; },
  });
  assert.equal(result.status, 413); assert.equal(called, false);
});

test("maps revoked access, busy and quota failures to recoverable UI messages", async () => {
  for (const status of [401, 404, 409, 429]) {
    const response = await handleAssistant(new Request(base), ["status"], { getSession: session, send: async () => { throw { status }; } });
    assert.equal(response.status, status);
    assert.equal(typeof (await response.json()).error, "string");
  }
});
