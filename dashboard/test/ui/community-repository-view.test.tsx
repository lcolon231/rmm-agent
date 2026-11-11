// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { mock, test } from "node:test";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

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

function refusing(t: { mock: { method: typeof mock.method } }, message = "Refused by server.") {
  return t.mock.method(globalThis, "fetch", async () => new Response(JSON.stringify({ error: message }), { status: 409 }));
}
function lastCall(fetchMock: ReturnType<typeof refusing>) {
  const [url, init] = fetchMock.mock.calls.at(-1)!.arguments as [string, RequestInit];
  return { url, body: JSON.parse(String(init.body)) };
}

test("a submission must be JSON and is forwarded unchanged", async (t) => {
  const fetchMock = refusing(t, "Signature does not verify.");
  view("operator", []);
  const submit = button("Submit for moderation") as HTMLButtonElement;
  assert.equal(submit.disabled, true);
  const area = screen.getByLabelText(/Submission JSON/);
  fireEvent.change(area, { target: { value: "not json" } });
  fireEvent.click(submit);
  assert.ok(await screen.findByText(/Paste the JSON produced/));
  assert.equal(fetchMock.mock.callCount(), 0);
  const submission = { manifest: { name: "x" }, content: "Get-Date", key_id: "k1", signature: "c2ln" };
  fireEvent.change(area, { target: { value: JSON.stringify(submission) } });
  fireEvent.click(submit);
  assert.ok(await screen.findByText("Signature does not verify."));
  assert.deepEqual(lastCall(fetchMock), { url: "/api/community/submissions", body: submission });
});

test("admins register publishers and keys through fixed paths", async (t) => {
  const fetchMock = refusing(t);
  view("admin", []);
  fireEvent.change(screen.getByLabelText("Namespace slug"), { target: { value: "contoso" } });
  fireEvent.change(screen.getByLabelText("Display name"), { target: { value: "Contoso" } });
  fireEvent.click(button("Register publisher")!);
  await screen.findAllByText("Refused by server.");
  assert.deepEqual(lastCall(fetchMock), { url: "/api/community/publishers", body: { slug: "contoso", display_name: "Contoso" } });
  const register = button("Register key") as HTMLButtonElement;
  assert.equal(register.disabled, true);
  fireEvent.change(screen.getByLabelText("Publisher"), { target: { value: "pub1" } });
  fireEvent.change(screen.getByLabelText("Key ID"), { target: { value: "acme-2027" } });
  fireEvent.change(screen.getByLabelText(/Ed25519 public key/), { target: { value: "-----BEGIN PUBLIC KEY-----" } });
  fireEvent.click(register);
  await waitFor(() => assert.equal(fetchMock.mock.callCount(), 2));
  assert.equal(lastCall(fetchMock).url, "/api/community/publishers/pub1/keys");
});

test("revocation and rejection require a reason and carry a request id", async (t) => {
  const fetchMock = refusing(t);
  view("admin", [pkg({})]);
  const revokePublisher = button("^Revoke publisher$") as HTMLButtonElement;
  assert.equal(revokePublisher.disabled, true);
  fireEvent.change(screen.getByLabelText("Revoke publisher reason"), { target: { value: "Key leaked" } });
  fireEvent.click(revokePublisher);
  await screen.findAllByText("Refused by server.");
  const revoke = lastCall(fetchMock);
  assert.equal(revoke.url, "/api/community/publishers/pub1/revoke");
  assert.match(revoke.body.request_id, /^revoke-/);
  fireEvent.change(screen.getByLabelText("Moderation reason"), { target: { value: "Unsafe" } });
  fireEvent.click(button("Reject")!);
  await waitFor(() => assert.equal(fetchMock.mock.callCount(), 2));
  assert.deepEqual(lastCall(fetchMock), { url: "/api/community/packages/p1/versions/1.0.0/moderation",
    body: { state: "rejected", reason: "Unsafe" } });
});

test("installs move forward by update and backward by rollback with exact acceptance", async (t) => {
  const fetchMock = refusing(t);
  const approved = (version: string, id: string): CommunityPackageVersion => ({ ...base, id, version, state: "approved",
    capability_escalation: [] });
  const catalog: CommunityPackage = { ...pkg({}), versions: [approved("2.0.0", "v3"), approved("1.5.0", "v2"), approved("1.0.0", "v1")] };
  const install: CommunityInstall = { id: "i1", package_id: "p1", qualified_name: "acme/net-check", script_id: "s1",
    script_version_id: "sv1", library_version: 2, installed_version: "1.5.0", installed_by: "admin@test",
    created_at: "2026-11-10T12:00:00Z", updated_at: "2026-11-10T12:00:00Z" };
  view("admin", [catalog], [install]);
  const select = screen.getByLabelText("Move to version");
  fireEvent.change(select, { target: { value: "2.0.0" } });
  const update = button("Update to v2.0.0") as HTMLButtonElement;
  assert.equal(update.disabled, true);
  const boxes = screen.getAllByRole("checkbox").filter((box) => box.closest(".community-install"));
  for (const box of boxes) fireEvent.click(box);
  fireEvent.click(update);
  await screen.findAllByText("Refused by server.");
  assert.equal(lastCall(fetchMock).url, "/api/community/installs/i1/update");
  fireEvent.change(select, { target: { value: "1.0.0" } });
  for (const box of screen.getAllByRole("checkbox").filter((item) => item.closest(".community-install"))) fireEvent.click(box);
  fireEvent.click(button("Roll back to v1.0.0")!);
  await waitFor(() => assert.equal(fetchMock.mock.callCount(), 2));
  const rollback = lastCall(fetchMock);
  assert.equal(rollback.url, "/api/community/installs/i1/rollback");
  assert.equal(rollback.body.version, "1.0.0");
});
