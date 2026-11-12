// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { AppRouterContext } from "next/dist/shared/lib/app-router-context.shared-runtime";
import { RevokeAction } from "@/components/enrollment/revoke-action";
import { BreakGlassView } from "@/components/break-glass-view";
import { SessionInventoryView } from "@/components/session-inventory-view";
import { enrollmentTabs } from "@/components/enrollment/enrollment-header";

test("readonly enrollment navigation hides provisioning destinations", () => {
  const tabs = enrollmentTabs("overview", "readonly");
  assert.equal(tabs.some((tab) => /installer|setup/.test(tab.href)), false);
});
test("agent revocation requires a bounded reason and preserves server refusal", async (t) => {
  let body: unknown;
  t.mock.method(globalThis, "fetch", async (_url: RequestInfo | URL, init?: RequestInit) => { body = JSON.parse(init?.body as string); return Response.json({ error: "Revocation refused" }, { status: 403 }); });
  render(<AppRouterContext.Provider value={{ refresh() {} } as never}><RevokeAction endpoint="/api/enrollment/agents/a1/revoke" kind="agent" label="Revoke agent" subject="Workstation" /></AppRouterContext.Provider>);
  fireEvent.click(screen.getByRole("button", { name: "Revoke agent" }));
  const dialog = within(screen.getByRole("alertdialog"));
  assert.equal((dialog.getByRole("button", { name: "Revoke agent" }) as HTMLButtonElement).disabled, true);
  fireEvent.change(dialog.getByRole("textbox"), { target: { value: "Retired device" } });
  fireEvent.click(dialog.getByRole("button", { name: "Revoke agent" }));
  await waitFor(() => assert.match(screen.getByRole("alertdialog").textContent ?? "", /Revocation refused/));
  assert.deepEqual(body, { reason: "Retired device" });
});
test("disabling emergency access requires a reason and sends the boolean unchanged", async (t) => {
  let body: unknown;
  t.mock.method(globalThis, "fetch", async (_url: RequestInfo | URL, init?: RequestInit) => { body = JSON.parse(init?.body as string); return Response.json({ error: "Not permitted" }, { status: 403 }); });
  render(<BreakGlassView initialError="" initialStatus={{ enabled: true, account_count: 1, unreviewed_activations: 0 }} initialActivations={[]} initialAccounts={[{ id: "b1", label: "Safe", credential_fingerprint: "a".repeat(64), created_at: "2026-01-01T00:00:00Z", created_by_email: null, rotated_at: null, last_activated_at: null, activation_count: 0, disabled_at: null, disabled_reason: null }]} />);
  fireEvent.click(screen.getByRole("button", { name: "Disable" }));
  const dialog = within(screen.getByRole("alertdialog"));
  assert.equal((dialog.getByRole("button", { name: "Confirm action" }) as HTMLButtonElement).disabled, true);
  fireEvent.change(dialog.getByRole("textbox"), { target: { value: "Credential retired" } });
  fireEvent.click(dialog.getByRole("button", { name: "Confirm action" }));
  await waitFor(() => assert.deepEqual(body, { disabled: true, reason: "Credential retired" }));
  assert.ok(await screen.findByText("Not permitted"));
});
test("unavailable sessions are not described as an empty session inventory", () => {
  render(<SessionInventoryView initialSessions={null} initialError="Session service unavailable" />);
  assert.match(screen.getByRole("alert").textContent ?? "", /unavailable/);
  assert.equal(screen.queryByRole("button"), null);
});

import { OperatorStatusAction } from "@/components/operator-account-actions";
import type { OperatorRecord } from "@/lib/operator-management-core";
test("operator disabling preserves the reason and final-administrator refusal", async (t) => {
  let body: unknown;
  t.mock.method(globalThis, "fetch", async (_url: RequestInfo | URL, init?: RequestInit) => { body = JSON.parse(init?.body as string); return Response.json({ error: "Final administrator cannot be disabled" }, { status: 409 }); });
  render(<OperatorStatusAction operator={{ id: "o1", email: "admin@example.test", role: "admin", disabled: false } as OperatorRecord} isCurrentOperator={false} onUpdated={() => assert.fail("Refused change must not update the record")} />);
  fireEvent.click(screen.getByRole("button", { name: "Disable" }));
  const dialog = within(screen.getByRole("alertdialog"));
  assert.equal((dialog.getByRole("button", { name: "Disable operator" }) as HTMLButtonElement).disabled, true);
  fireEvent.change(dialog.getByRole("textbox"), { target: { value: "Account retired" } });
  fireEvent.click(dialog.getByRole("button", { name: "Disable operator" }));
  await waitFor(() => assert.match(screen.getByRole("alertdialog").textContent ?? "", /Final administrator/));
  assert.deepEqual(body, { disabled: true, reason: "Account retired" });
});

