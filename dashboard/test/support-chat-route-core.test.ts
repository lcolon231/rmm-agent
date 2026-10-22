// SPDX-License-Identifier: AGPL-3.0-only
// Branch coverage for the end-user chat proxy (issue #281): the request
// guards, the streamed body bound, upstream refusals (expired token, rate
// limit) and the per-action response shaping.

import assert from "node:assert/strict";
import test from "node:test";

import { handleChat } from "../src/lib/support-chat-route-core.ts";

const id = "11111111-1111-4111-8111-111111111111";
const token = "a".repeat(43);
const rotatedToken = "b".repeat(43);
const origin = "https://dashboard.test";
const api = "https://api.test";
const expires = "2026-09-15T12:15:00Z";
const message = { seq: 4, sender: "end_user", body: "hello", created_at: "2026-09-15T12:00:00Z" };
const state = { status: "open", notice_version: "1", notice_acknowledged: false, retention_days: 30, token_expires_at: expires, messages: [message] };

const never: typeof fetch = async () => {
  throw new Error("must not reach the API");
};

function chatRequest(
  action: string,
  { method = "POST", body, headers = {}, search = "" }: { method?: string; body?: BodyInit; headers?: Record<string, string>; search?: string } = {},
) {
  return new Request(`${origin}/api/chat/${id}/${action}${search}`, {
    method,
    body,
    headers: { Authorization: `Bearer ${token}`, Origin: origin, "Content-Type": "application/json", ...headers },
    // A ReadableStream body is only accepted as a half-duplex upload.
    ...(body instanceof ReadableStream ? { duplex: "half" } : {}),
  } as RequestInit);
}

const call = (request: Request, action: string, fetchImpl: typeof fetch = never) =>
  handleChat(request, [id, action], api, fetchImpl);

// --------------------------------------------------------------------------- //
// Guards that refuse before any upstream call
// --------------------------------------------------------------------------- //
test("unknown paths, methods and GETs of non-message actions are refused", async () => {
  assert.equal((await handleChat(chatRequest("messages"), ["not-a-uuid", "messages"], api, never)).status, 400);
  assert.equal((await call(chatRequest("messages", { method: "DELETE" }), "messages")).status, 400);
  assert.equal((await call(chatRequest("notice", { method: "GET" }), "notice")).status, 400);
});

test("a missing or malformed chat bearer is a 401 pointing back at the app", async () => {
  for (const authorization of ["", "Bearer short", `Basic ${token}`, `Bearer ${token}=`]) {
    const response = await call(chatRequest("messages", { method: "GET", headers: { Authorization: authorization } }), "messages");
    assert.equal(response.status, 401, authorization);
    assert.match((await response.json()).error, /Open NodeLink Support/);
  }
});

test("a POST must be JSON and must parse", async () => {
  assert.equal((await call(chatRequest("messages", { body: "{}", headers: { "Content-Type": "text/plain" } }), "messages")).status, 400);
  assert.equal((await call(chatRequest("messages", { body: "{not json" }), "messages")).status, 400);
  assert.equal((await call(chatRequest("messages"), "messages")).status, 400, "an empty body is not JSON");
});

test("the size bound counts streamed bytes, not a caller-supplied Content-Length", async () => {
  let cancelled = false;
  const chunk = new TextEncoder().encode("x".repeat(16_384));
  let sent = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      // Three 16 KiB chunks: the third crosses the 32 KiB bound mid-stream.
      if (sent++ < 3) controller.enqueue(chunk);
      else controller.close();
    },
    cancel() {
      cancelled = true;
    },
  });
  const response = await call(chatRequest("messages", { body, headers: { "Content-Length": "2" } }), "messages");
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, "Message is too large.");
  assert.equal(cancelled, true, "the rest of the upload is not read");
});

test("a multi-chunk body under the bound is reassembled, including split UTF-8", async () => {
  const bytes = new TextEncoder().encode(JSON.stringify({ body: "héllo" }));
  const split = bytes.indexOf(0xc3) + 1; // cut inside the two-byte "é"
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes.slice(0, split));
      controller.enqueue(bytes.slice(split));
      controller.close();
    },
  });
  let forwarded: unknown;
  const response = await call(chatRequest("messages", { body }), "messages", async (_url, init) => {
    forwarded = init?.body;
    return Response.json(message);
  });
  assert.equal(response.status, 200);
  assert.deepEqual(JSON.parse(forwarded as string), { body: "héllo" });
});

// --------------------------------------------------------------------------- //
// Upstream refusals
// --------------------------------------------------------------------------- //
test("an expired chat token is passed through as 401 with its stable code", async () => {
  const response = await call(chatRequest("messages", { method: "GET" }), "messages", async () =>
    Response.json({ detail: { code: "support_chat_token_expired", message: "Bearer leaked" } }, { status: 401 }));
  assert.equal(response.status, 401);
  const body = await response.json();
  assert.deepEqual(body, { error: "Chat request could not be completed.", code: "support_chat_token_expired" });
});

test("a rate limit keeps 429 and tells the user to wait", async () => {
  const response = await call(chatRequest("messages", { body: "{}" }), "messages", async () =>
    Response.json({ detail: { code: "support_chat_rate_limited" } }, { status: 429 }));
  assert.equal(response.status, 429);
  assert.match((await response.json()).error, /wait a minute/);
});

test("codes outside the support_chat_ namespace are replaced, not echoed", async () => {
  for (const detail of [{ code: "internal_db_error" }, { code: 7 }, "plain string", null]) {
    const response = await call(chatRequest("messages", { method: "GET" }), "messages", async () =>
      Response.json({ detail }, { status: 409 }));
    assert.equal(response.status, 409);
    assert.equal((await response.json()).code, "support_chat_unavailable");
  }
});

test("an upstream that cannot be reached or returns non-JSON is a 503", async () => {
  const unreachable = await call(chatRequest("messages", { method: "GET" }), "messages", async () => {
    throw new TypeError("fetch failed");
  });
  assert.equal(unreachable.status, 503);
  const html = await call(chatRequest("messages", { method: "GET" }), "messages", async () => new Response("<html>"));
  assert.equal(html.status, 503);
});

// --------------------------------------------------------------------------- //
// Successful responses are re-shaped per action
// --------------------------------------------------------------------------- //
test("a polled tail forwards ?after and rejects a malformed state", async () => {
  let url = "";
  const good = await call(chatRequest("messages", { method: "GET", search: "?after=3" }), "messages", async (target) => {
    url = String(target);
    return Response.json(state);
  });
  assert.equal(url, `${api}/api/v1/support/chat/${id}/messages?after=3`);
  assert.deepEqual(await good.json(), state);

  const bad = await call(chatRequest("messages", { method: "GET" }), "messages", async () => Response.json({ ...state, status: "weird" }));
  assert.equal(bad.status, 502);
});

test("a sent message is returned only when it parses as a message", async () => {
  const good = await call(chatRequest("messages", { body: "{\"body\":\"hello\"}" }), "messages", async () =>
    Response.json({ ...message, internal: "dropped" }));
  assert.deepEqual(await good.json(), message);

  const bad = await call(chatRequest("messages", { body: "{}" }), "messages", async () => Response.json({ seq: 0 }));
  assert.equal(bad.status, 502);
  assert.match((await bad.json()).error, /could not be confirmed/);
});

test("a notice acknowledgement returns only the acknowledgement", async () => {
  const response = await call(chatRequest("notice", { body: "{}" }), "notice", async () =>
    Response.json({ acknowledged_by: "someone", notice_acknowledged: true }));
  assert.deepEqual(await response.json(), { notice_acknowledged: true });
});

test("a token refresh returns the rotated token only when it is well formed", async () => {
  const good = await call(chatRequest("refresh", { body: "{}" }), "refresh", async () =>
    Response.json({ token: rotatedToken, token_expires_at: expires, conversation_id: id }));
  assert.deepEqual(await good.json(), { token: rotatedToken, token_expires_at: expires });

  for (const raw of [
    null,
    { token: "short", token_expires_at: expires },
    { token: rotatedToken, token_expires_at: "not a date" },
    { token: rotatedToken },
  ]) {
    const response = await call(chatRequest("refresh", { body: "{}" }), "refresh", async () => Response.json(raw));
    assert.equal(response.status, 502, JSON.stringify(raw));
    assert.equal((await response.json()).error, "Session renewal failed.");
  }
});
