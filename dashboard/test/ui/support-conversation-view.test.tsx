// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";

import { SupportConversationView } from "@/components/support-conversation-view";
import type { OperatorTranscript } from "@/lib/support-chat-core";

const id = "22222222-2222-4222-8222-222222222222";
const hostile = `<img src=x onerror="globalThis.pwnedOperator=1"><b>bold</b>`;

function transcript(overrides: Partial<OperatorTranscript> = {}): OperatorTranscript {
  return {
    id, agent_id: "agent-1", endpoint: "FRONTDESK-01", subject: "Printer is offline", status: "open", opened_by: "end_user",
    messages: [
      { seq: 1, sender: "end_user", operator_email: null, body: hostile, created_at: "2026-10-21T12:00:00Z" },
      { seq: 2, sender: "technician", operator_email: "tech@example.test", body: "Looking now", created_at: "2026-10-21T12:01:00Z" },
    ],
    ...overrides,
  };
}

test("the thread shows the endpoint, status and context line without claiming consent the data does not show", () => {
  render(<SupportConversationView conversationId={id} initial={transcript()} />);

  assert.ok(screen.getByRole("heading", { name: "FRONTDESK-01" }));
  assert.ok(screen.getByText("Open"));
  assert.ok(screen.getByText("Printer is offline · Started by the user"));
  // The operator transcript carries no acknowledgment time, so no "accepted at" line.
  assert.doesNotMatch(document.body.textContent ?? "", /accepted/i);
  assert.ok(screen.getByText(/don’t ask for or share patient details/));
});

test("message bodies render as text on both sides of the thread", () => {
  render(<SupportConversationView conversationId={id} initial={transcript()} />);

  const log = screen.getByRole("list", { name: "Conversation" });
  assert.ok(log.textContent?.includes(hostile));
  assert.equal(log.querySelector("img, b"), null);
  assert.equal((globalThis as { pwnedOperator?: number }).pwnedOperator, undefined);
  assert.ok(within(log).getByText("tech@example.test"));
  assert.ok(within(log).getByText("User"));
});

test("Send posts the same reply body to the reply route", async (t) => {
  const fetchMock = t.mock.method(globalThis, "fetch", async () =>
    new Response(JSON.stringify({ seq: 3, sender: "technician", operator_email: null, body: "On my way", created_at: "2026-10-21T12:02:00Z" }), { status: 201 }));
  render(<SupportConversationView conversationId={id} initial={transcript()} />);

  const send = screen.getByRole("button", { name: "Send" });
  assert.equal((send as HTMLButtonElement).disabled, true, "an empty reply cannot be sent");
  fireEvent.change(screen.getByLabelText("Reply"), { target: { value: "On my way" } });
  fireEvent.click(send);

  const log = screen.getByRole("list", { name: "Conversation" });
  await waitFor(() => assert.ok(within(log).getByText("On my way")));
  await waitFor(() => assert.equal((screen.getByLabelText("Reply") as HTMLTextAreaElement).value, ""));
  const [url, init] = fetchMock.mock.calls[0].arguments as [string, RequestInit];
  assert.equal(url, `/api/support/conversations/${id}/messages`);
  assert.equal(init.method, "POST");
  assert.equal(init.body, JSON.stringify({ body: "On my way" }));
});

test("a refused reply is shown and the draft is kept", async (t) => {
  t.mock.method(globalThis, "fetch", async () => new Response(JSON.stringify({ error: "This conversation is closed." }), { status: 409 }));
  render(<SupportConversationView conversationId={id} initial={transcript()} />);

  fireEvent.change(screen.getByLabelText("Reply"), { target: { value: "Hello" } });
  fireEvent.click(screen.getByRole("button", { name: "Send" }));

  assert.equal((await screen.findByRole("alert")).textContent, "This conversation is closed.");
  assert.equal((screen.getByLabelText("Reply") as HTMLTextAreaElement).value, "Hello");
});

test("Close conversation posts to the close route and then locks the composer", async (t) => {
  const fetchMock = t.mock.method(globalThis, "fetch", async () => new Response("{}", { status: 200 }));
  render(<SupportConversationView conversationId={id} initial={transcript()} />);

  fireEvent.click(screen.getByRole("button", { name: "Close conversation" }));

  await waitFor(() => assert.ok(screen.getByText("This conversation is closed.")));
  const [url, init] = fetchMock.mock.calls[0].arguments as [string, RequestInit];
  assert.equal(url, `/api/support/conversations/${id}/close`);
  assert.equal(init.method, "POST");
  assert.equal(init.body, undefined);
  assert.equal((screen.getByRole("button", { name: "Closed" }) as HTMLButtonElement).disabled, true);
  assert.equal((screen.getByLabelText("Reply") as HTMLTextAreaElement).disabled, true);
  assert.equal((screen.getByRole("button", { name: "Send" }) as HTMLButtonElement).disabled, true);
});

test("a closed conversation cannot be replied to", () => {
  render(<SupportConversationView conversationId={id} initial={transcript({ status: "closed" })} />);

  assert.ok(screen.getByText("Closed", { selector: "span" }));
  assert.equal((screen.getByLabelText("Reply") as HTMLTextAreaElement).disabled, true);
  assert.equal((screen.getByRole("button", { name: "Closed" }) as HTMLButtonElement).disabled, true);
});

test("an unavailable conversation says nothing was changed and offers the way back", () => {
  render(<SupportConversationView conversationId={id} initial={null} />);

  const alert = screen.getByRole("alert");
  assert.match(alert.textContent ?? "", /could not be loaded/);
  assert.match(alert.textContent ?? "", /Nothing was changed\./);
  assert.equal(screen.getByRole("link", { name: "Back to Support chat" }).getAttribute("href"), "/support");
  assert.equal(screen.queryByLabelText("Reply"), null);
});
