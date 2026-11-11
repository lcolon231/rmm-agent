// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { fireEvent, render, screen } from "@testing-library/react";

import { CommunityRepositoryView } from "@/components/community-repository-view";
import type { CommunityInstall, CommunityPackage, CommunityPackageVersion, CommunityPublisher } from "@/lib/community-packages-core";

const HEX = "b".repeat(64);
const base: CommunityPackageVersion = {
  id: "v1", version: "1.0.0", state: "submitted", language: "powershell", content_sha256: HEX, content_bytes: 40,
  manifest_sha256: HEX, signing_key_id: "acme-2026", signing_key_fingerprint: HEX,
  capabilities: ["network.egress", "platform.windows", "script.run.powershell"], supported_platforms: ["windows"],
  description: null, submitted_by: "op@test", submitted_at: "2026-11-10T10:00:00Z", revoked_at: null,
  moderation: null, capability_escalation: ["network.egress"],
};
const publisher: CommunityPublisher = {
  id: "pub1", slug: "acme", display_name: "Acme", status: "active", created_by: "admin@test",
  created_at: "2026-11-10T09:00:00Z", revoked_at: null, revoked_by: null,
  keys: [{ key_id: "acme-2026", fingerprint: HEX, status: "active", created_by: "admin@test", created_at: "2026-11-10T09:00:00Z", revoked_at: null }],
};
function pkg(version: Partial<CommunityPackageVersion>): CommunityPackage {
  return { id: "p1", publisher: "acme", name: "net-check", qualified_name: "acme/net-check", publisher_status: "active",
    created_at: "2026-11-10T10:00:00Z", updated_at: "2026-11-10T10:00:00Z", versions: [{ ...base, ...version }] };
}
function view(role: "readonly" | "operator" | "admin", packages: CommunityPackage[], installs: CommunityInstall[] = []) {
  render(<CommunityRepositoryView publishers={[publisher]} packages={packages} installs={installs} initialError="" role={role} />);
}
const button = (name: string) => screen.queryByRole("button", { name: new RegExp(name) });

test("readonly viewers see evidence but no submit, moderation, or install controls", () => {
  view("readonly", [pkg({})]);
  assert.ok(screen.getByText("acme/net-check"));
  assert.ok(screen.getByText("network.egress (new)"));
  assert.equal(button("Submit for moderation"), null);
  assert.equal(button("Approve"), null);
  assert.equal(button("Install"), null);
  assert.equal(button("Revoke"), null);
});

test("approval of an escalated version is disabled until the escalation is acknowledged", () => {
  view("admin", [pkg({})]);
  fireEvent.change(screen.getByLabelText("Moderation reason"), { target: { value: "Reviewed source" } });
  const approve = button("Approve") as HTMLButtonElement;
  assert.equal(approve.disabled, true);
  fireEvent.click(screen.getByLabelText(/I reviewed the added capabilities/));
  assert.equal(approve.disabled, false);
});

test("install requires accepting every declared capability and sends the exact set", async (t) => {
  const approved = pkg({ state: "approved", capability_escalation: [], moderation: {
    state: "approved", moderated_by: "mod@test", reason_sha256: HEX, reason_bytes: 8,
    acknowledged_capability_escalation: true, created_at: "2026-11-10T11:00:00Z" } });
  const fetchMock = t.mock.method(globalThis, "fetch", async () => new Response(JSON.stringify({ error: "Install refused." }), { status: 409 }));
  view("admin", [approved]);
  const install = button("Install into script library") as HTMLButtonElement;
  assert.equal(install.disabled, true);
  for (const capability of base.capabilities) fireEvent.click(screen.getByLabelText(capability));
  assert.equal(install.disabled, false);
  fireEvent.click(install);
  assert.ok(await screen.findByText("Install refused."));
  const [url, init] = fetchMock.mock.calls[0].arguments as [string, RequestInit];
  assert.equal(url, "/api/community/installs");
  const body = JSON.parse(String(init.body));
  assert.deepEqual([...body.accepted_capabilities].sort(), [...base.capabilities].sort());
  assert.equal(body.package_id, "p1");
});

test("blocked versions offer no install and show why", () => {
  view("admin", [pkg({ state: "blocked" })]);
  assert.ok(screen.getByText("Blocked (publisher or key revoked)"));
  assert.equal(button("Install"), null);
  assert.equal(button("Approve"), null);
});

test("a load failure renders a fail-closed notice instead of records", () => {
  render(<CommunityRepositoryView publishers={null} packages={null} installs={null} initialError="Could not verify." role="admin" />);
  assert.ok(screen.getByRole("alert"));
  assert.equal(screen.queryByText("acme/net-check"), null);
});
