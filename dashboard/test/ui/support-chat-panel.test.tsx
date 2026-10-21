// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { render, screen, waitFor } from "@testing-library/react";

import { SupportChatPanel } from "@/components/support-chat-panel";

const conversation = "11111111-1111-4111-8111-111111111111";
const token = "T".repeat(43);
const hostile = `<img src=x onerror="globalThis.pwned=1"><b>bold</b>`;

const chatState = {
  status: "open",
  notice_version: "1",
  notice_acknowledged: true,
  retention_days: 30,
  token_expires_at: "2099-01-01T00:00:00Z",
  messages: [{ seq: 1, sender: "technician", body: hostile, created_at: "2026-10-21T12:00:00Z" }],
};

function visit(path: string) {
  window.history.replaceState(null, "", path);
}

test("the chat token is read from the fragment, sent as a header, and scrubbed from the address bar", async (t) => {
  const fetchMock = t.mock.method(globalThis, "fetch", async () => new Response(JSON.stringify(chatState), { status: 200 }));
  visit(`/support/chat#c=${conversation}&t=${token}&expires=2099-01-01T00%3A00%3A00Z`);
  render(<SupportChatPanel />);

  await waitFor(() => assert.equal(fetchMock.mock.callCount(), 1));
  assert.equal(window.location.hash, "");
  assert.ok(!window.location.href.includes(token));

  const [url, init] = fetchMock.mock.calls[0].arguments as [string, RequestInit];
  assert.equal(url, `/api/chat/${conversation}/messages?after=0`);
  assert.ok(!url.includes(token));
  assert.equal(init.credentials, "omit");
  assert.equal((init.headers as Record<string, string>).Authorization, `Bearer ${token}`);
});

test("a token in the query string is ignored", async (t) => {
  const fetchMock = t.mock.method(globalThis, "fetch", async () => new Response("{}"));
  visit(`/support/chat?c=${conversation}&t=${token}&expires=2099-01-01T00%3A00%3A00Z`);
  render(<SupportChatPanel />);

  assert.equal((await screen.findByRole("alert")).textContent, "Open NodeLink Support on your computer to start a session.");
  assert.equal(fetchMock.mock.callCount(), 0);
});

test("message bodies render as text, never as markup", async (t) => {
  t.mock.method(globalThis, "fetch", async () => new Response(JSON.stringify(chatState), { status: 200 }));
  visit(`/support/chat#c=${conversation}&t=${token}&expires=2099-01-01T00%3A00%3A00Z`);
  render(<SupportChatPanel />);

  const conversationLog = await screen.findByRole("list", { name: "Conversation" });
  await waitFor(() => assert.ok(conversationLog.textContent?.includes(hostile)));
  assert.equal(conversationLog.querySelector("img, b"), null);
  assert.equal((globalThis as { pwned?: number }).pwned, undefined);
});
