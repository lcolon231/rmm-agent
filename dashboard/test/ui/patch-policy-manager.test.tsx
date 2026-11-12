// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { AppRouterContext } from "next/dist/shared/lib/app-router-context.shared-runtime";
import { PatchPolicyManager } from "@/components/patch-policy-manager";
import type { PatchApprovalPolicy } from "@/lib/patch-policies-core";

const policy: PatchApprovalPolicy = { id: "p1", name: "Baseline", scope: "global", scope_id: null, enabled: true, created_at: "2026-01-01T00:00:00Z", current_version: 1, rule_count: 0, default_action: "deny", require_maintenance_window: true, reboot_policy: "never", reboot_delay_seconds: 300, reboot_requires_no_user: true, max_install_attempts: 2 };
function visit(canAdmin: boolean) {
  return render(<AppRouterContext.Provider value={{ refresh() {} } as never}><PatchPolicyManager initialPolicies={[policy]} canAdmin={canAdmin} /></AppRouterContext.Provider>);
}

test("read-only policy review exposes no mutations, including inside the drawer", () => {
  visit(false);
  fireEvent.click(screen.getByRole("row", { name: "Show rules for Baseline" }));
  assert.equal(screen.queryByRole("button", { name: /New policy|Delete policy|Disable policy/ }), null);
});

test("policy deletion requires a reason and preserves the existing delete request and refusal", async (t) => {
  const calls: RequestInit[] = [];
  t.mock.method(globalThis, "fetch", async (_url, init) => {
    calls.push(init as RequestInit);
    return Response.json({ error: "Permission denied." }, { status: 403 });
  });
  visit(true);
  fireEvent.click(screen.getByRole("row", { name: "Show rules for Baseline" }));
  fireEvent.click(screen.getByRole("button", { name: "Delete policy" }));
  const dialog = within(screen.getByRole("alertdialog"));
  const confirm = dialog.getByRole("button", { name: "Delete policy" }) as HTMLButtonElement;
  assert.equal(confirm.disabled, true);
  fireEvent.change(dialog.getByRole("textbox"), { target: { value: "Retiring baseline" } });
  fireEvent.click(confirm);
  await waitFor(() => assert.match(screen.getByRole("alertdialog").textContent ?? "", /Permission denied/));
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, "DELETE");
  assert.equal(calls[0].body, undefined);
  assert.ok(screen.getByRole("row", { name: "Show rules for Baseline" }));
});
