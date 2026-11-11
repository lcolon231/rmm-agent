// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";
import {
  compareSemver, effectCapabilitiesOf, installFromUnknown, packageFromUnknown, packageListFromUnknown,
  publisherFromUnknown, sameCapabilitySet, versionStateLabel,
} from "../src/lib/community-packages-core.ts";
import { handleCommunityAction, resolveCommunityRoute } from "../src/lib/community-packages-route-core.ts";

const HEX = "a".repeat(64);
const version = { id: "v1", version: "1.0.0", state: "approved", language: "powershell", content_sha256: HEX,
  content_bytes: 42, manifest_sha256: HEX, signing_key_id: "acme-2026", signing_key_fingerprint: HEX,
  capabilities: ["filesystem.write", "platform.windows", "script.run.powershell"], supported_platforms: ["windows"],
  description: null, submitted_by: "op@test", submitted_at: "2026-11-10T10:00:00Z", revoked_at: null,
  moderation: { state: "approved", moderated_by: "mod@test", reason_sha256: HEX, reason_bytes: 9,
    acknowledged_capability_escalation: true, created_at: "2026-11-10T11:00:00Z" },
  capability_escalation: ["filesystem.write"] };
const pkg = { id: "p1", publisher: "acme", name: "temp-cleanup", qualified_name: "acme/temp-cleanup",
  publisher_status: "active", created_at: "2026-11-10T10:00:00Z", updated_at: "2026-11-10T10:00:00Z", versions: [version] };
const install = { id: "i1", package_id: "p1", qualified_name: "acme/temp-cleanup", script_id: "s1",
  script_version_id: "sv1", library_version: 1, installed_version: "1.0.0", installed_by: "admin@test",
  created_at: "2026-11-10T12:00:00Z", updated_at: "2026-11-10T12:00:00Z" };
const publisher = { id: "pub1", slug: "acme", display_name: "Acme", status: "active", created_by: "admin@test",
  created_at: "2026-11-10T09:00:00Z", revoked_at: null, revoked_by: null,
  keys: [{ key_id: "acme-2026", fingerprint: HEX, status: "active", created_by: "admin@test", created_at: "2026-11-10T09:00:00Z", revoked_at: null }] };

function request(body: unknown, origin = "https://dashboard.test") {
  return new Request("https://dashboard.test/api/community/x", {
    method: "POST", headers: { "Content-Type": "application/json", Origin: origin }, body: JSON.stringify(body),
  });
}
function session(role: "readonly" | "operator" | "admin") {
  return async () => ({ kind: "authenticated" as const, operator: { role }, sessionToken: "server-secret" });
}

test("package parsers allowlist fields and refuse contract drift", () => {
  const parsed = packageFromUnknown({ ...pkg, secret: "sentinel", versions: [{ ...version, content: "Remove-Item", signature: "sig" }] });
  assert.ok(parsed);
  assert.doesNotMatch(JSON.stringify(parsed), /sentinel|Remove-Item|"signature"/);
  assert.equal(packageFromUnknown({ ...pkg, qualified_name: "other/temp-cleanup" }), null);
  assert.equal(packageFromUnknown({ ...pkg, versions: [{ ...version, state: "trusted" }] }), null);
  assert.equal(packageFromUnknown({ ...pkg, versions: [{ ...version, capabilities: ["kernel.load"] }] }), null);
  assert.equal(packageFromUnknown({ ...pkg, versions: [{ ...version, version: "1.0" }] }), null);
  assert.equal(packageFromUnknown({ ...pkg, versions: [{ ...version, manifest_sha256: "abc" }] }), null);
  assert.equal(packageListFromUnknown({ items: [pkg], total: 1 })?.total, 1);
  assert.equal(packageListFromUnknown({ items: [pkg] }), null);
  assert.ok(publisherFromUnknown(publisher));
  assert.equal(publisherFromUnknown({ ...publisher, status: "trusted" }), null);
  assert.ok(installFromUnknown(install));
  assert.equal(installFromUnknown({ ...install, library_version: 0 }), null);
});

test("capability helpers require the exact declared set", () => {
  assert.ok(sameCapabilitySet(["b", "a"], ["a", "b"]));
  assert.ok(!sameCapabilitySet(["a"], ["a", "b"]));
  assert.ok(!sameCapabilitySet(["a", "a"], ["a"]));
  assert.deepEqual(effectCapabilitiesOf(version.capabilities), ["filesystem.write"]);
  assert.ok(compareSemver("1.10.0", "1.9.9") > 0);
  assert.equal(compareSemver("2.0.0", "2.0.0"), 0);
  assert.match(versionStateLabel("blocked"), /revoked/);
});

test("route resolver maps only allowlisted paths", () => {
  assert.deepEqual(resolveCommunityRoute(["submissions"]), { action: "submit", params: {} });
  assert.deepEqual(resolveCommunityRoute(["packages", "p1", "versions", "1.0.0", "moderation"]),
    { action: "moderate", params: { packageId: "p1", version: "1.0.0" } });
  assert.deepEqual(resolveCommunityRoute(["installs", "i1", "rollback"]), { action: "rollback", params: { installId: "i1" } });
  assert.deepEqual(resolveCommunityRoute(["publishers", "pub1", "keys", "k1", "revoke"]),
    { action: "revokeKey", params: { publisherId: "pub1", keyId: "k1" } });
  assert.equal(resolveCommunityRoute(["packages", "p1", "versions", "../x", "moderation"]), null);
  assert.equal(resolveCommunityRoute(["installs", "i1", "delete"]), null);
  assert.equal(resolveCommunityRoute([]), null);
});

test("mutations are same-origin and role-gated before reaching the API", async () => {
  let calls = 0;
  const deps = (role: "readonly" | "operator" | "admin") => ({
    getSession: session(role), mutate: async () => { calls += 1; return pkg; },
  });
  const moderation = { state: "approved", reason: "Looks right", acknowledge_capability_escalation: true };
  const params = { packageId: "p1", version: "1.0.0" };
  assert.equal((await handleCommunityAction(request(moderation, "https://evil.test"), "moderate", params, deps("admin"))).status, 403);
  assert.equal((await handleCommunityAction(request(moderation), "moderate", params, deps("operator"))).status, 403);
  const submission = { manifest: { schema: "x" }, content: "Get-Date", key_id: "acme-2026", signature: "c2ln" };
  assert.equal((await handleCommunityAction(request(submission), "submit", {}, deps("readonly"))).status, 403);
  assert.equal(calls, 0);
  const ok = await handleCommunityAction(request(moderation), "moderate", params, deps("admin"));
  assert.equal(ok.status, 200);
  assert.equal(calls, 1);
});

test("request bodies are allowlisted and paths are encoded server-side", async () => {
  let seen: { path: string; body: unknown; token: string } | null = null;
  const deps = { getSession: session("admin"), mutate: async (token: string, path: string, body: unknown) => {
    seen = { path, body, token }; return install; } };
  const extra = await handleCommunityAction(request({ version: "1.1.0", accepted_capabilities: [], request_id: "update-0001", force: true }),
    "update", { installId: "i1" }, deps);
  assert.equal(extra.status, 400);
  const badCap = await handleCommunityAction(request({ version: "1.1.0", accepted_capabilities: ["root"], request_id: "update-0001" }),
    "update", { installId: "i1" }, deps);
  assert.equal(badCap.status, 400);
  const response = await handleCommunityAction(request({ version: "1.1.0", accepted_capabilities: ["platform.windows"], request_id: "update-0001" }),
    "update", { installId: "i/../1" }, deps);
  assert.equal(response.status, 200);
  assert.deepEqual(seen, { path: "/installs/i%2F..%2F1/update", token: "server-secret",
    body: { version: "1.1.0", accepted_capabilities: ["platform.windows"], request_id: "update-0001" } });
  assert.doesNotMatch(JSON.stringify(await response.json()), /server-secret/);
});

test("server refusal codes map to fixed operator messages", async () => {
  const failing = (status: number, code: string | null) => ({
    getSession: session("admin"),
    mutate: async () => { throw Object.assign(new Error("x"), { status, code }); },
  });
  const body = { state: "approved", reason: "Looks right" };
  const params = { packageId: "p1", version: "1.0.0" };
  const escalation = await handleCommunityAction(request(body), "moderate", params, failing(409, "capability_escalation_unacknowledged"));
  assert.equal(escalation.status, 409);
  assert.deepEqual(await escalation.json(), { error: "This version adds capabilities; acknowledge the escalation to approve it.",
    code: "capability_escalation_unacknowledged" });
  const selfReview = await handleCommunityAction(request(body), "moderate", params, failing(403, "moderation_self_review_forbidden"));
  assert.equal((await selfReview.json()).code, "moderation_self_review_forbidden");
  const unknown = await handleCommunityAction(request(body), "moderate", params, failing(409, "internal_detail_leak"));
  assert.deepEqual(await unknown.json(), { error: "The repository changed. Refresh and try again." });
  const outage = await handleCommunityAction(request(body), "moderate", params, failing(500, null));
  assert.equal(outage.status, 503);
  const invalid = await handleCommunityAction(request(body), "moderate", params,
    { getSession: session("admin"), mutate: async () => ({ id: "p1" }) });
  assert.equal(invalid.status, 502);
});
