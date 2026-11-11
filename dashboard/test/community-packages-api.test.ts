// SPDX-License-Identifier: AGPL-3.0-only
// The server-only community repository client and its catch-all BFF route,
// driven through the real `nodelinkApiRequest` against a scripted fetch.
import assert from "node:assert/strict";
import test from "node:test";

import {
  communityMutation, listCommunityInstalls, listCommunityPackages, listCommunityPublishers,
} from "@/lib/community-packages";
import { POST } from "@/app/api/community/[...path]/route";
import { fakeApi, jsonResponse } from "./support/fake-api.ts";

const HEX = "c".repeat(64);
const publisher = { id: "pub1", slug: "acme", display_name: "Acme", status: "active", created_by: "a@test",
  created_at: "2026-11-10T09:00:00Z", revoked_at: null, revoked_by: null, keys: [] };
const pkg = { id: "p1", publisher: "acme", name: "tool", qualified_name: "acme/tool", publisher_status: "active",
  created_at: "2026-11-10T09:00:00Z", updated_at: "2026-11-10T09:00:00Z", versions: [{
    id: "v1", version: "1.0.0", state: "submitted", language: "shell", content_sha256: HEX, content_bytes: 4,
    manifest_sha256: HEX, signing_key_id: "k1", signing_key_fingerprint: HEX,
    capabilities: ["platform.linux", "script.run.shell"], supported_platforms: ["linux"], description: "d",
    submitted_by: "op@test", submitted_at: "2026-11-10T09:00:00Z", revoked_at: null, moderation: null,
    capability_escalation: [] }] };
const install = { id: "i1", package_id: "p1", qualified_name: "acme/tool", script_id: "s1", script_version_id: "sv1",
  library_version: 1, installed_version: "1.0.0", installed_by: "a@test",
  created_at: "2026-11-10T09:00:00Z", updated_at: "2026-11-10T09:00:00Z" };

test("list loaders call the community API with the session and parse fail-closed", async (t) => {
  const calls = fakeApi(t, (call) => {
    const path = new URL(call.url).pathname;
    if (path.endsWith("/publishers")) return jsonResponse(200, { items: [publisher] });
    if (path.endsWith("/packages")) return jsonResponse(200, { items: [pkg], total: 1 });
    return jsonResponse(200, { items: [install] });
  });
  assert.equal((await listCommunityPublishers("tok"))[0].slug, "acme");
  assert.equal((await listCommunityPackages("tok")).total, 1);
  assert.equal((await listCommunityInstalls("tok"))[0].installed_version, "1.0.0");
  assert.deepEqual(calls.map((call) => new URL(call.url).pathname + new URL(call.url).search), [
    "/api/v1/community/publishers", "/api/v1/community/packages?page_size=100", "/api/v1/community/installs",
  ]);
  assert.equal(calls[0].headers.get("Authorization"), "Bearer tok");
});

test("malformed list responses are refused rather than rendered", async (t) => {
  fakeApi(t, () => jsonResponse(200, { items: [{ id: "x" }], total: 1 }));
  await assert.rejects(listCommunityPublishers("tok"), /Invalid publisher list/);
  await assert.rejects(listCommunityPackages("tok"), /Invalid package list/);
  await assert.rejects(listCommunityInstalls("tok"), /Invalid install list/);
});

test("mutations post JSON to the fixed path and parse by result kind", async (t) => {
  const responses = [publisher, pkg, install, { id: "bad" }];
  const calls = fakeApi(t, () => jsonResponse(200, responses.shift()));
  assert.equal((await communityMutation("tok", "/publishers", { slug: "acme" }, "publisher")).id, "pub1");
  assert.equal((await communityMutation("tok", "/submissions", {}, "package")).id, "p1");
  assert.equal((await communityMutation("tok", "/installs", {}, "install")).id, "i1");
  await assert.rejects(communityMutation("tok", "/installs", {}, "install"), /Invalid community repository response/);
  assert.equal(calls[0].method, "POST");
  assert.equal(new URL(calls[0].url).pathname, "/api/v1/community/publishers");
  assert.equal(calls[0].body, JSON.stringify({ slug: "acme" }));
});

test("the catch-all route refuses unknown actions and cross-origin requests", async () => {
  const request = (origin: string) => new Request("https://dashboard.test/api/community/x", {
    method: "POST", headers: { Origin: origin, "Content-Type": "application/json" }, body: "{}",
  });
  const unknown = await POST(request("https://dashboard.test") as never, { params: Promise.resolve({ path: ["installs", "i1", "delete"] }) });
  assert.equal(unknown.status, 404);
  const crossOrigin = await POST(request("https://evil.test") as never, { params: Promise.resolve({ path: ["submissions"] }) });
  assert.equal(crossOrigin.status, 403);
});
