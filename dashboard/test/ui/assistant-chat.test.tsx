// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";

import { AssistantChat } from "@/components/assistant/assistant-chat";

const CLIENT = "55555555-5555-4555-8555-555555555555";
const CONVERSATION = "66666666-6666-4666-8666-666666666666";
const clients = [{ id: CLIENT, name: "Lakeshore" }];
const hostile = `<img src=x onerror="globalThis.pwnedAssistant=1">`;

function json(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), { status });
}

test("unavailable states explain why and never show a composer", () => {
  for (const [state, copy] of [
    ["disabled", "The assistant is not enabled for this operator."],
    ["unconfigured", "The assistant is awaiting server configuration."],
    ["unavailable", "The assistant is temporarily unavailable."],
  ] as const) {
    const { unmount } = render(<AssistantChat clients={clients} state={state} />);
    assert.ok(screen.getByText(copy));
    assert.equal(screen.getByRole("link", { name: "Open endpoints" }).getAttribute("href"), "/endpoints");
    assert.equal(screen.queryByLabelText("Ask about the selected client"), null);
    unmount();
  }
});

test("the thread states scope and read-only, and the notice only claims what the server enforces", (t) => {
  t.mock.method(globalThis, "fetch", async () => json({ items: [] }));
  render(<AssistantChat clients={clients} initialClientId={CLIENT} state="available" />);

  assert.ok(screen.getByText("Looking at: Lakeshore · read-only"));
  const text = document.body.textContent ?? "";
  assert.match(text, /cannot run commands or change devices or settings/);
  assert.match(text, /sent to an external AI service/);
  assert.match(text, /Don’t type patient details/);
  assert.doesNotMatch(text, /never sees patient records/i);
  assert.doesNotMatch(text, /Approvals/);
});

test("without a client nothing can be sent", () => {
  render(<AssistantChat clients={clients} state="available" />);

  assert.ok(screen.getByText("No client selected · read-only"));
  assert.equal((screen.getByLabelText("Ask about the selected client") as HTMLTextAreaElement).disabled, true);
  assert.equal((screen.getByRole("button", { name: "Send" }) as HTMLButtonElement).disabled, true);
  assert.equal((screen.getByRole("button", { name: "New conversation" }) as HTMLButtonElement).disabled, true);
});

test("Send creates a conversation and a run with the same request bodies, and answers render as text", async (t) => {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  t.mock.method(globalThis, "fetch", async (url: string, init?: RequestInit) => {
    requests.push({ url, init });
    if (url.startsWith("/api/assistant/conversations?")) return json({ items: [] });
    if (url === "/api/assistant/conversations") return json({ id: CONVERSATION, expires_at: "2099-01-01T00:00:00Z", runs: [] }, 201);
    return json({
      id: CONVERSATION, expires_at: "2099-01-01T00:00:00Z",
      runs: [{ id: "r1", request_id: "q1", status: "completed", created_at: "2026-10-21T12:00:00Z", question: "Which endpoints are offline?", answer: hostile,
        evidence: [{ tool: "list_endpoints", outcome: "observed", data: { items: [] }, sources: [{ endpoint_id: "e1", label: "FRONTDESK-01", last_seen_at: null, observed_at: "2026-10-21T12:00:00Z" }] }] }],
    });
  });
  render(<AssistantChat clients={clients} initialClientId={CLIENT} state="available" />);

  fireEvent.change(screen.getByLabelText("Ask about the selected client"), { target: { value: "Which endpoints are offline?" } });
  fireEvent.click(screen.getByRole("button", { name: "Send" }));

  const log = screen.getByRole("log", { name: "Assistant conversation" });
  await waitFor(() => assert.ok(within(log).getByText("Completed")));
  assert.ok(log.textContent?.includes(hostile));
  assert.equal(log.querySelector("img"), null);
  assert.equal((globalThis as { pwnedAssistant?: number }).pwnedAssistant, undefined);
  assert.equal(within(log).getByRole("link", { name: "FRONTDESK-01" }).getAttribute("href"), "/endpoints/e1");

  const create = requests.find((r) => r.url === "/api/assistant/conversations");
  assert.equal(create?.init?.method, "POST");
  assert.equal(create?.init?.body, JSON.stringify({ client_id: CLIENT }));
  const run = requests.find((r) => r.url === `/api/assistant/conversations/${CONVERSATION}/runs`);
  const body = JSON.parse(String(run?.init?.body));
  assert.deepEqual(Object.keys(body), ["request_id", "message"]);
  assert.equal(body.message, "Which endpoints are offline?");
  assert.ok(screen.getByRole("heading", { name: "Which endpoints are offline?" }));
});

test("a failed run is labelled Failed, never Completed", async (t) => {
  t.mock.method(globalThis, "fetch", async (url: string) => {
    if (url.startsWith("/api/assistant/conversations?")) return json({ items: [{ id: CONVERSATION, created_at: "2026-10-21T12:00:00Z", expires_at: "2099-01-01T00:00:00Z" }] });
    return json({ id: CONVERSATION, expires_at: "2099-01-01T00:00:00Z",
      runs: [{ id: "r1", request_id: "q1", status: "failed", created_at: "2026-10-21T12:00:00Z", question: "Summarize patch compliance.", answer: "", evidence: [] }] });
  });
  render(<AssistantChat clients={clients} initialClientId={CLIENT} state="available" />);

  const history = screen.getByRole("region", { name: "Private conversation history" });
  fireEvent.click(await within(history).findByRole("button", { name: new Date("2026-10-21T12:00:00Z").toLocaleString() }));

  const log = screen.getByRole("log", { name: "Assistant conversation" });
  await waitFor(() => assert.ok(within(log).getByText("Failed")));
  assert.equal(within(log).queryByText("Completed"), null);
  assert.ok(within(log).getByRole("button", { name: "Retry investigation" }));
});
