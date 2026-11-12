// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { EmergencyOverrideView } from "@/components/emergency-override-view";
import type { EmergencyOverride } from "@/lib/emergency-overrides-core";
const row: EmergencyOverride = { id: "e1", agent_id: "agent1", client_id: null, site_id: null, kind: "reboot", status: "active", payload_sha256: "a".repeat(64), policy_id: "p1", required_approvals: 1, activated_by_email: "admin@example.test", activated_by_operator_id: "o1", justification: "Emergency incident with no reviewer available", created_at: "2026-01-01T00:00:00Z", expires_at: "2099-01-01T00:00:00Z", consumed_at: null, revoked_at: null, revoked_by_email: null, notified_at: null, notification_error: "provider_unavailable", notified_recipient_count: 0, reviewed_at: null, reviewed_by_email: null };
function show(admin = true) { render(<EmergencyOverrideView initialError="" initialOverrides={[row]} initialEndpoints={[]} viewerOperatorId="o1" viewerIsAdmin={admin} />); }
test("an activator cannot review their own override and notification failure remains visible", () => {
 show(); fireEvent.click(screen.getByRole("row", { name: /Open reboot override/ }));
 assert.equal(screen.queryByRole("button", { name: "Mark as reviewed" }), null);
 assert.ok(screen.getByText("You activated this override, so someone else must review it."));
 assert.match(screen.getByRole("dialog").textContent ?? "", /not notified|unavailable|failed/i);
});
test("running an override requires confirmation while preserving the bodyless API and refusal", async (t) => {
 const fetchMock=t.mock.method(globalThis, "fetch", async () => Response.json({ error: "Override expired" }, { status: 409 }));
 show(); fireEvent.click(screen.getByRole("row", { name: /Open reboot override/ })); fireEvent.click(screen.getByRole("button", { name: "Run now" }));
 const dialog=within(screen.getByRole("alertdialog")); const button=dialog.getByRole("button", { name: "Run now" }) as HTMLButtonElement;
 assert.equal(button.disabled,true); fireEvent.change(dialog.getByRole("textbox"),{target:{value:"Restore service"}}); fireEvent.click(button);
 assert.ok(await dialog.findByText("Override expired"));
 const [url,init]=fetchMock.mock.calls[0].arguments as unknown as [string,RequestInit]; assert.equal(url,"/api/emergency-overrides/e1/run"); assert.equal(init.body,undefined);
});
test("read-only review exposes no override creation action", () => { show(false); assert.equal(screen.queryByRole("button", { name: "Request an override" }),null); });
