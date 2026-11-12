// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { AppRouterContext } from "next/dist/shared/lib/app-router-context.shared-runtime";
import { AlertActionsProvider, AlertHeaderActions, AlertWorkPanel } from "@/components/alert-actions";
import { AlertsView } from "@/components/alerts/alerts-view";
import type { ReactNode } from "react";

function visit(children: ReactNode) { render(<AppRouterContext.Provider value={{ refresh() {} } as never}>{children}</AppRouterContext.Provider>); }
function actions(canManage: boolean) { return <AlertActionsProvider alert={{ id: "a1", state: "open", version: 4, assigned_to_operator_id: null }} assignees={[]} canManage={canManage}><AlertHeaderActions /><AlertWorkPanel /></AlertActionsProvider>; }
test("readonly alert review has no acknowledge, resolve or assignment controls", () => {
  visit(actions(false));
  assert.equal(screen.queryByRole("button"), null);
  assert.ok(screen.getByText(/read-only access/));
});
test("resolving forwards the reason as a note and preserves optimistic concurrency", async (t) => {
  let sent: Record<string, unknown> | undefined;
  t.mock.method(globalThis, "fetch", async (_url: RequestInfo | URL, init?: RequestInit) => { sent = JSON.parse(init?.body as string); return Response.json({ error: "Version changed. Refresh." }, { status: 409 }); });
  visit(actions(true));
  fireEvent.click(screen.getByRole("button", { name: "Resolve alert" }));
  const dialog = within(screen.getByRole("alertdialog"));
  assert.equal((dialog.getByRole("button", { name: "Resolve alert" }) as HTMLButtonElement).disabled, true);
  fireEvent.change(dialog.getByRole("textbox"), { target: { value: "Verified recovery" } });
  fireEvent.click(dialog.getByRole("button", { name: "Resolve alert" }));
  await waitFor(() => assert.match(screen.getByRole("alertdialog").textContent ?? "", /Version changed/));
  assert.equal(sent?.comment, "Verified recovery");
  assert.equal(sent?.expected_version, 4);
  assert.equal(typeof sent?.request_id, "string");
});
test("a failed alert list displays neither a table nor a reassuring empty state", () => {
  visit(<AlertsView filter="active" rows={null} loaded={0} counts={null} unassigned={null} />);
  assert.equal(screen.queryByRole("table"), null);
  assert.match(screen.getByRole("alert").textContent ?? "", /Nothing was changed/);
});
