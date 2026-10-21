// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { mock, test } from "node:test";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { AppRouterContext, type AppRouterInstance } from "next/dist/shared/lib/app-router-context.shared-runtime";

import { CommandDispatchForm } from "@/components/command-dispatch-form";
import { MAX_SCRIPT_BYTES } from "@/lib/command-console-core";

const endpointId = "agent-1";
const hostname = "WS-042";

function renderForm(props: { canExecuteScripts: boolean; isAdmin: boolean }) {
  const refresh = mock.fn();
  const router = { refresh, push: mock.fn(), replace: mock.fn(), back: mock.fn(), forward: mock.fn(), prefetch: mock.fn() };
  render(
    <AppRouterContext.Provider value={router as unknown as AppRouterInstance}>
      <CommandDispatchForm
        endpointId={endpointId}
        hostname={hostname}
        maintenanceTarget={{ agentId: endpointId, siteId: null, clientId: null }}
        maintenanceWindows={[]}
        serverNowMs={Date.parse("2026-10-21T12:00:00Z")}
        {...props}
      />
    </AppRouterContext.Provider>,
  );
  return { refresh };
}

const kindOptions = () =>
  Array.from((screen.getByLabelText("Command kind") as HTMLSelectElement).options, (option) => option.value);
const chooseKind = (kind: string) => fireEvent.change(screen.getByLabelText("Command kind"), { target: { value: kind } });
const review = () => fireEvent.click(screen.getByRole("button", { name: "Review dispatch" }));

test("a read-only operator never sees script or administrator-governed kinds", () => {
  renderForm({ canExecuteScripts: false, isAdmin: false });
  assert.deepEqual(kindOptions(), ["collect_inventory", "scan_updates"]);
  assert.equal(screen.queryByLabelText("Script"), null);
  assert.equal(screen.queryByText("Managed boundary"), null);
});

test("scripts over the 56 KiB bound stop at review and never reach the network", async (t) => {
  const fetchMock = t.mock.method(globalThis, "fetch", async () => new Response("{}"));
  renderForm({ canExecuteScripts: true, isAdmin: false });
  assert.ok(kindOptions().includes("powershell"));
  assert.ok(!kindOptions().includes("registry_write"));

  // Multi-byte characters count by encoded size, not string length.
  fireEvent.change(screen.getByLabelText("Script"), { target: { value: "é".repeat(MAX_SCRIPT_BYTES / 2 + 1) } });
  review();
  assert.equal(screen.getByRole("alert").textContent, "Enter a script within the size limit before dispatching.");
  assert.equal(screen.queryByRole("region", { name: "Confirm command dispatch" }), null);

  fireEvent.change(screen.getByLabelText("Script"), { target: { value: "a".repeat(MAX_SCRIPT_BYTES) } });
  review();
  assert.ok(screen.getByRole("region", { name: "Confirm command dispatch" }));
  assert.equal(fetchMock.mock.callCount(), 0);
});

test("governed kinds carry their boundary notice and withhold registry data from the transcript", () => {
  renderForm({ canExecuteScripts: true, isAdmin: true });
  chooseKind("registry_write");
  assert.match(screen.getByRole("note").textContent ?? "", /^Managed boundaryOnly HKLM\/HKCU Software\\NodeLink\\Managed /);

  fireEvent.change(screen.getByLabelText("Value name"), { target: { value: "Ring" } });
  fireEvent.change(screen.getByLabelText("Value data"), { target: { value: "canary-secret-value" } });
  review();
  const transcript = screen.getByRole("region", { name: "Confirm command dispatch" }).textContent ?? "";
  assert.ok(transcript.includes("[value withheld from confirmation transcript]"));
  assert.ok(!transcript.includes("canary-secret-value"));
});

test("a power action without a covering window warns before review and demands the hostname", () => {
  renderForm({ canExecuteScripts: false, isAdmin: true });
  chooseKind("reboot");
  assert.match(screen.getByText("No maintenance window covers this endpoint").textContent ?? "", /No maintenance window/);
  fireEvent.change(screen.getByLabelText("Operational reason"), { target: { value: "Monthly patch reboot, ticket 4411" } });
  fireEvent.change(screen.getByLabelText(/to confirm/), { target: { value: "ws-042" } });
  review();
  assert.equal(screen.getByRole("alert").textContent, `Enter a reason, delay and consent policy, then type ${hostname} exactly.`);
});

test("confirming posts the reviewed input once and refreshes the endpoint", async (t) => {
  const fetchMock = t.mock.method(globalThis, "fetch", async () =>
    new Response(JSON.stringify({ command: { id: "cmd-9" } }), { status: 201 }));
  const { refresh } = renderForm({ canExecuteScripts: true, isAdmin: false });
  fireEvent.change(screen.getByLabelText("Script"), { target: { value: "Get-Service" } });
  review();
  fireEvent.click(screen.getByRole("button", { name: /Confirm dispatch/ }));
  assert.ok(await screen.findByText("Command signed and queued"));

  assert.equal(fetchMock.mock.callCount(), 1);
  const [url, init] = fetchMock.mock.calls[0].arguments as [string, RequestInit];
  assert.equal(url, `/api/endpoints/${endpointId}/commands`);
  assert.equal(JSON.parse(String(init.body)).script, "Get-Service");
  await waitFor(() => assert.equal(refresh.mock.callCount(), 1));
  assert.equal(screen.getByRole("link", { name: "Follow this command" }).getAttribute("href"), `/endpoints/${endpointId}/commands/cmd-9`);
});
