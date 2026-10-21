// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  handleCloseConversation,
  handleGetTranscript,
  handleListConversations,
  handlePostReply,
  handleStartConversation,
  handleUnreadCount,
} from "../src/lib/support-route-core.ts";
import {
  SENTINEL,
  apiError,
  bffContract,
  request,
  revokedSession,
  sessionFor,
  upstream,
} from "./bff-contract.ts";

const conversationId = "0b6f5c1e-7d1a-4a52-9f53-6f0d9a1c2b3e";
const conversation = {
  id: conversationId,
  agent_id: "agent-1",
  endpoint: "PC-1",
  subject: null,
  status: "open",
  opened_by: "end_user",
  last_message_at: null,
  created_at: "2026-10-21T12:00:00Z",
  unread: 2,
  end_user_token: SENTINEL,
};
const message = { seq: 1, sender: "technician", operator_email: null, body: "Hi", created_at: "2026-10-21T12:00:00Z", ip: SENTINEL };
const transcript = { ...conversation, messages: [message] };
const path = `/api/support/conversations/${conversationId}`;

bffContract([
  {
    name: "list conversations",
    minRole: "operator",
    mutation: false,
    upstreamResult: [conversation],
    invoke: ({ getSession, call }) =>
      handleListConversations(request("/api/support/conversations"), { getSession, getSupportConversations: call }),
  },
  {
    name: "get transcript",
    minRole: "operator",
    mutation: false,
    upstreamResult: transcript,
    invoke: ({ getSession, call }) =>
      handleGetTranscript(request(path), conversationId, { getSession, getSupportTranscript: call }),
  },
  {
    name: "post reply",
    minRole: "operator",
    mutation: true,
    upstreamResult: message,
    invoke: ({ getSession, origin, call }) =>
      handlePostReply(request(`${path}/messages`, "POST", { body: "Hi" }, origin), conversationId, {
        getSession,
        postSupportReply: call,
      }),
  },
  {
    name: "close conversation",
    minRole: "operator",
    mutation: true,
    upstreamResult: { status: "closed", leaked: SENTINEL },
    invoke: ({ getSession, origin, call }) =>
      handleCloseConversation(request(`${path}/close`, "POST", undefined, origin), conversationId, {
        closeSupportConversation: call,
        getSession,
      }),
  },
  {
    name: "start conversation",
    minRole: "operator",
    mutation: true,
    upstreamResult: { conversation_id: conversationId, chat_token: SENTINEL },
    invoke: ({ getSession, origin, call }) =>
      handleStartConversation(request("/api/endpoints/agent-1/support-chat", "POST", undefined, origin), "agent-1", {
        getSession,
        startSupportConversation: call,
      }),
  },
]);

test("unread count: a revoked session is refused before forwarding", async () => {
  const double = upstream(3);
  const response = await handleUnreadCount(request("/api/support/unread-count"), {
    getSession: revokedSession,
    getSupportUnreadCount: double.fn,
  });
  assert.equal(response.status, 401);
  assert.equal(double.calls.length, 0);
});

test("unread count: readonly reads zero without forwarding; failures read zero", async () => {
  const double = upstream(3);
  const readonly = await handleUnreadCount(request("/x"), { getSession: sessionFor("readonly"), getSupportUnreadCount: double.fn });
  assert.deepEqual(await readonly.json(), { unread: 0 });
  assert.equal(double.calls.length, 0);

  const operator = await handleUnreadCount(request("/x"), { getSession: sessionFor("operator"), getSupportUnreadCount: double.fn });
  assert.deepEqual(await operator.json(), { unread: 3 });

  const failed = await handleUnreadCount(request("/x"), {
    getSession: sessionFor("operator"),
    getSupportUnreadCount: async () => { throw apiError(500); },
  });
  assert.equal(failed.status, 200);
  assert.deepEqual(await failed.json(), { unread: 0 });
});

test("reply bodies are validated before forwarding", async () => {
  for (const body of ["{bad", { body: "" }, { body: "   " }, { body: 7 }, { body: "é".repeat(2049) }]) {
    const double = upstream(message);
    const response = await handlePostReply(request(`${path}/messages`, "POST", body), conversationId, {
      getSession: sessionFor("operator"),
      postSupportReply: double.fn,
    });
    assert.equal(response.status, 400);
    assert.equal(double.calls.length, 0);
  }
});

test("a reply without an Origin header is refused", async () => {
  const double = upstream(message);
  const response = await handlePostReply(request(`${path}/messages`, "POST", { body: "Hi" }, null), conversationId, {
    getSession: sessionFor("operator"),
    postSupportReply: double.fn,
  });
  assert.equal(response.status, 403);
  assert.equal(double.calls.length, 0);
});

test("start conversation maps service codes to fixed text", async () => {
  for (const [status, code, text] of [
    [409, "support_chat_unsupported", /must be updated/],
    [409, "support_chat_agent_untrusted", /not trusted/],
    [503, "support_chat_not_configured", /not configured/],
    [404, null, /not found/],
  ] as const) {
    const response = await handleStartConversation(request("/x", "POST"), "agent-1", {
      getSession: sessionFor("operator"),
      startSupportConversation: async () => { throw apiError(status, code); },
    });
    assert.equal(response.status, status);
    assert.match((await response.json()).error, text);
  }
});

test("upstream failures never echo upstream detail", async () => {
  const failing = async () => { throw Object.assign(new Error(SENTINEL), { status: 500 }); };
  const responses = [
    await handleListConversations(request("/x"), { getSession: sessionFor("operator"), getSupportConversations: failing }),
    await handleGetTranscript(request("/x"), conversationId, { getSession: sessionFor("operator"), getSupportTranscript: failing }),
    await handleCloseConversation(request("/x", "POST"), conversationId, { getSession: sessionFor("operator"), closeSupportConversation: failing }),
  ];
  for (const response of responses) {
    assert.equal(response.status, 502);
    assert.ok(!(await response.text()).includes(SENTINEL));
  }
});
