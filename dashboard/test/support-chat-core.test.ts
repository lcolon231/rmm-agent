// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";
import {
  readChatAccess,
  mergeMessages,
  chatApiPath,
  chatStateFromUnknown,
  operatorConversationsFromUnknown,
  operatorTranscriptFromUnknown,
  totalUnread,
  formatChatTimestamp,
  type ChatMessage,
  type OperatorConversation,
} from "../src/lib/support-chat-core.ts";
import { handleChat } from "../src/lib/support-chat-route-core.ts";

const id = "11111111-1111-4111-8111-111111111111";
const token = "a".repeat(43);
const message = (seq: number): ChatMessage => ({ seq, sender: "end_user", body: "hello", created_at: "2026-09-15T12:00:00Z" });
const state = { status: "open", notice_version: "1", notice_acknowledged: false, retention_days: 30, token_expires_at: "2026-09-15T12:15:00Z", messages: [] };

test("chat access requires a scoped token and expiry in a fragment", () => {
  assert.equal(readChatAccess(""), null);
  assert.equal(readChatAccess(`#c=${id}&t=bad&expires=bad`), null);
  assert.equal(readChatAccess(`#c=${id}&t=${token}&expires=2026-09-15T12%3A00%3A00Z`)?.conversation, id);
});
test("repeated tails and a send arriving before a poll preserve every sequence", () => {
  assert.deepEqual(mergeMessages([message(1), message(3)], [message(2), message(3)]).map(m => m.seq), [1, 2, 3]);
  assert.deepEqual(mergeMessages([message(1)], [message(1)]), [message(1)]);
});
test("chat proxy cannot forward arbitrary routes or token queries", () => {
  assert.equal(chatApiPath([id, "refresh"], ""), `/api/v1/support/chat/${id}/refresh`);
  for (const parts of [[id, "close"], ["../agents", "messages"], [id, "messages", "extra"]]) assert.equal(chatApiPath(parts, ""), null);
  assert.equal(chatApiPath([id, "messages"], "?t=secret"), null);
  assert.equal(chatApiPath([id, "messages"], "?after=-1"), null);
});
test("payload parser drops credentials and rejects malformed message arrays", () => {
  assert.deepEqual(chatStateFromUnknown({ ...state, token: "secret" }), state);
  assert.equal(chatStateFromUnknown({ ...state, messages: [{ body: "secret" }] }), null);
  assert.equal(chatStateFromUnknown({ ...state, token_expires_at: "bad" }), null);
});
function request(method = "GET", origin = "https://dashboard.test", body?: string) {
  return new Request(`https://dashboard.test/api/chat/${id}/messages`, { method, headers: { Authorization: `Bearer ${token}`, Origin: origin, "Content-Type": "application/json" }, body });
}
test("proxy forwards only chat auth and returns no-store sanitized responses", async () => {
  const response = await handleChat(request(), [id, "messages"], "https://api.test", async (url, options) => {
    assert.equal(String(url), `https://api.test/api/v1/support/chat/${id}/messages`);
    assert.deepEqual(options?.headers, { Authorization: `Bearer ${token}`, "Content-Type": "application/json" });
    assert.equal(options?.redirect, "error");
    return Response.json({ ...state, token: "must-not-leak" });
  });
  assert.equal(response.headers.get("Cache-Control"), "no-store");
  assert.deepEqual(await response.json(), state);
});
test("proxy refuses cross-origin sends and oversized streamed bodies", async () => {
  const never = async () => { throw new Error("must not fetch"); };
  assert.equal((await handleChat(request("POST", "https://evil.test", "{}"), [id, "messages"], "https://api.test", never)).status, 403);
  assert.equal((await handleChat(request("POST", "https://dashboard.test", "x".repeat(32769)), [id, "messages"], "https://api.test", never)).status, 400);
});
test("upstream secrets and exception bodies never become browser errors", async () => {
  const response = await handleChat(request(), [id, "messages"], "https://api.test", async () => Response.json({ detail: "Bearer private-secret" }, { status: 500 }));
  assert.equal(response.status, 503);
  assert.ok(!(await response.text()).includes("private-secret"));
});

// --- Operator (technician) side (#235) --------------------------------------
const conversation = (over: Partial<OperatorConversation> = {}): OperatorConversation => ({
  id, agent_id: "agent-1", endpoint: "PC-1", subject: "vpn", status: "open",
  opened_by: "end_user", last_message_at: "2026-09-16T12:00:00Z", created_at: "2026-09-16T11:00:00Z", unread: 2, ...over,
});

test("operator conversation list parses and rejects malformed rows", () => {
  const parsed = operatorConversationsFromUnknown({ conversations: [conversation()] });
  assert.equal(parsed?.length, 1);
  assert.equal(parsed?.[0].unread, 2);
  assert.equal(operatorConversationsFromUnknown({ conversations: [{ ...conversation(), status: "weird" }] }), null);
  assert.equal(operatorConversationsFromUnknown({ conversations: [{ ...conversation(), unread: -1 }] }), null);
  assert.equal(operatorConversationsFromUnknown({}), null);
});

test("totalUnread sums only non-negative unread across conversations", () => {
  assert.equal(totalUnread([conversation({ unread: 2 }), conversation({ id, unread: 3 })]), 5);
  assert.equal(totalUnread([]), 0);
});

test("operator transcript parses identity and rejects malformed messages", () => {
  const parsed = operatorTranscriptFromUnknown({
    id, agent_id: "agent-1", endpoint: "PC-1", subject: "vpn", status: "open", opened_by: "end_user",
    messages: [
      { seq: 1, sender: "end_user", operator_email: null, body: "hi", created_at: "2026-09-16T12:00:00Z" },
      { seq: 2, sender: "technician", operator_email: "tech@nodelink.test", body: "hello", created_at: "2026-09-16T12:01:00Z" },
    ],
  });
  assert.equal(parsed?.messages.length, 2);
  assert.equal(parsed?.messages[1].operator_email, "tech@nodelink.test");
  assert.equal(operatorTranscriptFromUnknown({ id, agent_id: "a", status: "open", opened_by: "end_user", messages: [{ body: "x" }] }), null);
});

test("mergeMessages dedupes and orders transcript messages without dropping any", () => {
  const m = (seq: number, sender: "end_user" | "technician") => ({ seq, sender, operator_email: null, body: `b${seq}`, created_at: "2026-09-16T12:00:00Z" });
  const merged = mergeMessages([m(1, "end_user"), m(2, "technician")], [m(2, "technician"), m(3, "end_user")]);
  assert.deepEqual(merged.map((x) => x.seq), [1, 2, 3]);
});

test("formatChatTimestamp handles null and invalid input", () => {
  assert.equal(formatChatTimestamp(null), "");
  assert.equal(formatChatTimestamp("not-a-date"), "");
  assert.ok(formatChatTimestamp("2026-09-16T12:00:00Z").length > 0);
});
