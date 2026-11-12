// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { AppRouterContext } from "next/dist/shared/lib/app-router-context.shared-runtime";
import { MaintenanceWindowManager } from "@/components/maintenance-window-manager";
import type { MaintenanceWindow } from "@/lib/maintenance-windows-core";

const windowRecord: MaintenanceWindow = { id: "w1", name: "Planned maintenance", scope: "global", scope_id: null, starts_at: "2099-01-01T00:00:00Z", ends_at: "2099-01-01T01:00:00Z", timezone: "UTC", recurrence: null, created_by: "operator", created_at: "2026-01-01T00:00:00Z" };
function visit(canManage: boolean) {
  render(<AppRouterContext.Provider value={{ refresh() {} } as never}><MaintenanceWindowManager initialWindows={[windowRecord]} clients={[]} sites={[]} endpoints={[]} canManage={canManage} serverNowMs={Date.now()} prefill={{ scope: null, scopeId: null, name: null, coverSeconds: null, returnPath: null }} /></AppRouterContext.Provider>);
}

test("readonly maintenance review hides creation and ending controls", () => {
  visit(false);
  fireEvent.click(screen.getByRole("row", { name: "Show schedule for Planned maintenance" }));
  assert.equal(screen.queryByRole("button", { name: /New window|End window/ }), null);
  assert.ok(within(screen.getByRole("dialog")).getByText("Waiting", { exact: true }));
});

test("ending a window preserves exact-name confirmation and also requires a reason", async (t) => {
  const calls: RequestInit[] = [];
  t.mock.method(globalThis, "fetch", async (_url: RequestInfo | URL, init?: RequestInit) => {
    calls.push(init as RequestInit);
    return Response.json({ error: "Permission denied." }, { status: 403 });
  });
  visit(true);
  fireEvent.click(screen.getByRole("row", { name: "Show schedule for Planned maintenance" }));
  const end = screen.getByRole("button", { name: "End window" }) as HTMLButtonElement;
  assert.equal(end.disabled, true);
  fireEvent.change(screen.getByRole("textbox"), { target: { value: windowRecord.name } });
  fireEvent.click(end);
  const dialog = within(screen.getByRole("alertdialog"));
  const confirm = dialog.getByRole("button", { name: "End window" }) as HTMLButtonElement;
  assert.equal(confirm.disabled, true);
  fireEvent.change(dialog.getByRole("textbox"), { target: { value: "Cancelled maintenance" } });
  fireEvent.click(confirm);
  await waitFor(() => assert.match(screen.getByRole("alertdialog").textContent ?? "", /Permission denied/));
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, "DELETE");
  assert.deepEqual(JSON.parse(calls[0].body as string), { confirm_name: windowRecord.name });
});

test("creating a future window never claims it is already open", async (t) => {
  const start = Date.now() + 86400000;
  t.mock.method(globalThis, "fetch", async () => Response.json({ window: { ...windowRecord, starts_at: new Date(start).toISOString(), ends_at: new Date(start + 3600000).toISOString() } }));
  render(<AppRouterContext.Provider value={{ refresh() {} } as never}><MaintenanceWindowManager initialWindows={[]} clients={[]} sites={[]} endpoints={[]} canManage serverNowMs={start} prefill={{ scope: "global", scopeId: null, name: windowRecord.name, coverSeconds: null, returnPath: null }} /></AppRouterContext.Provider>);
  fireEvent.click(screen.getByRole("button", { name: "Create window" }));
  await waitFor(() => assert.ok(screen.getByText(/was created · Not open yet/)));
  assert.equal(screen.queryByText(/Planned maintenance is open/), null);
});

