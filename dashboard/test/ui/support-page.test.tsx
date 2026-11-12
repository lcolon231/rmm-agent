// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { beforeEach, mock, test } from "node:test";
import { render, screen, within } from "@testing-library/react";
import type { ReactElement } from "react";

import type { DashboardSessionState } from "@/lib/dashboard-auth-core";
import type { OperatorConversation, OperatorTranscript } from "@/lib/support-chat-core";

class NavigationSignal extends Error {}

const OPEN_ID = "33333333-3333-4333-8333-333333333333";
const CLOSED_ID = "44444444-4444-4444-8444-444444444444";

let session: DashboardSessionState = { kind: "anonymous" };
let listFail = false;
let transcriptFail = false;
const calls: string[] = [];

function conversation(overrides: Partial<OperatorConversation>): OperatorConversation {
  return {
    id: OPEN_ID, agent_id: "agent-1", endpoint: "FRONTDESK-01", subject: "Printer is offline", status: "open",
    opened_by: "end_user", last_message_at: "2026-10-21T12:00:00Z", created_at: "2026-10-21T11:00:00Z", unread: 3, ...overrides,
  };
}

const LIST = [
  conversation({ id: CLOSED_ID, endpoint: "LAB-WS-02", subject: null, status: "closed", unread: 0 }),
  conversation({}),
];

const TRANSCRIPT: OperatorTranscript = {
  id: OPEN_ID, agent_id: "agent-1", endpoint: "FRONTDESK-01", subject: "Printer is offline", status: "open", opened_by: "technician",
  messages: [{ seq: 1, sender: "end_user", operator_email: null, body: "It will not print", created_at: "2026-10-21T12:00:00Z" }],
};

mock.module("@/lib/dashboard-session", { namedExports: { getDashboardSession: async () => session } });
mock.module("@/lib/support", {
  namedExports: {
    getSupportConversations: async () => {
      calls.push("list");
      if (listFail) throw new Error("down");
      return LIST;
    },
    getSupportTranscript: async (_token: string, conversationId: string) => {
      calls.push(`transcript:${conversationId}`);
      if (transcriptFail) throw new Error("not found");
      return TRANSCRIPT;
    },
  },
});
mock.module("next/navigation", {
  namedExports: { redirect: (to: string) => { throw new NavigationSignal(`redirect:${to}`); } },
});

const { default: SupportPage } = await import("@/app/support/page");
const { default: SupportConversationPage } = await import("@/app/support/[conversationId]/page");

beforeEach(() => {
  session = { kind: "authenticated", sessionToken: "tok", operator: { id: "op", email: "op@example.test", role: "operator" } } as DashboardSessionState;
  listFail = false;
  transcriptFail = false;
  calls.length = 0;
});

test("signed-out visitors are sent to sign in before any conversation loads", async () => {
  session = { kind: "anonymous" };
  await assert.rejects(SupportPage(), /redirect:\/login/);
  assert.deepEqual(calls, []);
});

test("the queue lists open conversations first with unread counts in words", async () => {
  render((await SupportPage()) as ReactElement);

  assert.ok(screen.getByRole("heading", { level: 1, name: "Support chat" }));
  const list = screen.getByRole("list", { name: "Open and closed conversations" });
  const rows = within(list).getAllByRole("link");
  assert.match(rows[0].textContent ?? "", /FRONTDESK-01/);
  assert.match(rows[0].textContent ?? "", /3 unread/);
  assert.match(rows[1].textContent ?? "", /LAB-WS-02/);
  assert.match(rows[1].textContent ?? "", /Closed · No subject/);
  assert.equal(rows[0].getAttribute("href"), `/support/${OPEN_ID}`);
  assert.ok(screen.getByText("1 open · 1 closed"));
  assert.ok(screen.getByText("Select a conversation"));
});

test("a failed queue says nothing was changed and shows no rows", async () => {
  listFail = true;
  render((await SupportPage()) as ReactElement);

  const alert = screen.getByRole("alert");
  assert.match(alert.textContent ?? "", /could not be loaded/);
  assert.match(alert.textContent ?? "", /Nothing was changed\./);
  assert.equal(screen.queryByRole("list", { name: "Open and closed conversations" }), null);
});

test("a conversation page loads the transcript before the list and marks the open row", async () => {
  render((await SupportConversationPage({ params: Promise.resolve({ conversationId: OPEN_ID }) })) as ReactElement);

  assert.deepEqual(calls, [`transcript:${OPEN_ID}`, "list"]);
  const current = screen.getAllByRole("link").find((link) => link.getAttribute("aria-current") === "page" && link.getAttribute("href") === `/support/${OPEN_ID}`);
  assert.ok(current, "the selected conversation is marked as the current row");
  assert.ok(screen.getByText("Printer is offline · Started by a technician"));
  assert.ok(screen.getByText("It will not print"));
});

test("a failed list never hides the thread", async () => {
  listFail = true;
  render((await SupportConversationPage({ params: Promise.resolve({ conversationId: OPEN_ID }) })) as ReactElement);

  assert.ok(screen.getByText("It will not print"));
  assert.ok(screen.getByLabelText("Reply"));
  assert.match(screen.getByRole("alert").textContent ?? "", /Support chat could not be loaded/);
});

test("a missing conversation renders the unavailable state without a composer", async () => {
  transcriptFail = true;
  render((await SupportConversationPage({ params: Promise.resolve({ conversationId: OPEN_ID }) })) as ReactElement);

  assert.ok(screen.getByText("Conversation unavailable"));
  assert.equal(screen.queryByLabelText("Reply"), null);
});
