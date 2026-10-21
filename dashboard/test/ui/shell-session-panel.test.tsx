// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import { ShellSessionPanel } from "@/components/shell-session-panel";

const session = { id: "sess-1", agent_id: "agent-1", status: "active", client_last_seq: 0, agent_last_seq: 0 };
const hostile = `<script>globalThis.pwned=1</script><img src=x onerror="globalThis.pwned=1">ünïcode\n`;
const b64 = (text: string) => Buffer.from(text, "utf8").toString("base64");

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status });
}

test("an untrusted endpoint cannot open a shell", () => {
  render(<ShellSessionPanel canExecuteScripts capable endpointId="agent-1" trusted={false} />);
  assert.equal((screen.getByRole("button", { name: /Open shell/ }) as HTMLButtonElement).disabled, true);
  assert.ok(screen.getByText("This endpoint is quarantined or revoked, so a live shell cannot be opened."));
});

test("endpoint output is rendered as text, never as markup", async (t) => {
  const responses = [
    json({ session }),
    json({ session, frames: [{ seq: 1, stream: "stdout", data_b64: b64(hostile), eof: false, byte_length: 0 }] }),
    json({ session: { ...session, status: "closed" }, frames: [] }),
  ];
  const fetchMock = t.mock.method(globalThis, "fetch", async () => responses.shift() ?? json({ session: { ...session, status: "closed" }, frames: [] }));
  render(<ShellSessionPanel canExecuteScripts capable endpointId="agent-1" trusted />);
  fireEvent.click(screen.getByRole("button", { name: /Open shell/ }));

  const log = await screen.findByRole("log", { name: "Live shell output" });
  await waitFor(() => assert.ok(log.textContent?.includes(hostile)));
  assert.equal(log.querySelector("script, img"), null);
  assert.equal((globalThis as { pwned?: number }).pwned, undefined);

  const [openUrl, openInit] = fetchMock.mock.calls[0].arguments as [string, RequestInit];
  assert.equal(openUrl, "/api/endpoints/agent-1/shell-sessions");
  assert.equal(openInit.method, "POST");
  assert.equal(fetchMock.mock.calls[1].arguments[0], "/api/endpoints/agent-1/shell-sessions/sess-1/output?after=0&ack=0");
});

test("a refused output poll stops the stream with the server's reason", async (t) => {
  const responses = [json({ session }), json({ error: "Session belongs to another operator." }, 403)];
  const fetchMock = t.mock.method(globalThis, "fetch", async () => responses.shift() ?? json({ error: "unexpected" }, 500));
  render(<ShellSessionPanel canExecuteScripts capable endpointId="agent-1" trusted />);
  fireEvent.click(screen.getByRole("button", { name: /Open shell/ }));
  await waitFor(() => assert.equal(screen.getByRole("alert").textContent, "Session belongs to another operator."));
  assert.equal(fetchMock.mock.callCount(), 2);
});
