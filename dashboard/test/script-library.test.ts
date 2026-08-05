// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";
import { scriptItemFromUnknown, scriptListFromUnknown, scriptState } from "../src/lib/script-library-core.ts";
import { handleScriptCreate, handleScriptDeprecate, handleScriptReview } from "../src/lib/script-library-route-core.ts";

const version = { id: "version-1", version: 1, language: "powershell", content_sha256: "a".repeat(64), content_bytes: 11,
  description: "Collect health", tags: ["diagnostic"], supported_platforms: ["windows"], created_by: "operator@test", created_at: "2026-08-05T10:00:00Z", review: null };
const script = { id: "script-1", name: "Collect health", latest_version: 1, record_version: 1, deprecated_at: null, deprecated_by: null,
  created_by: "operator@test", created_at: "2026-08-05T10:00:00Z", updated_at: "2026-08-05T10:00:00Z", latest: version, versions: [version] };
function request(path: string, body: unknown, origin = "https://dashboard.test") { return new Request(`https://dashboard.test${path}`, { method: "POST", headers: { "Content-Type": "application/json", Origin: origin }, body: JSON.stringify(body) }); }
function session(role: "readonly" | "operator" | "admin") { return async () => ({ kind: "authenticated" as const, operator: { role }, sessionToken: "server-secret" }); }

test("script response parsers allowlist metadata and express lifecycle state", () => {
  const parsed = scriptItemFromUnknown({ ...script, password: "sentinel", latest: { ...version, content: "secret source", token: "sentinel" } });
  assert.ok(parsed); assert.equal(scriptState(parsed), "draft");
  assert.doesNotMatch(JSON.stringify(parsed), /sentinel|password|token|secret source|\"content\":/);
  assert.equal(scriptListFromUnknown({ items: [script], page: 1, page_size: 50, total: 1 })?.total, 1);
  assert.equal(scriptItemFromUnknown({ ...script, latest: { ...version, language: "python" } }), null);
});

test("script creation rejects cross-origin and readonly requests", async () => {
  const body = { name: "Collect health", language: "powershell", content: "Get-Service", tags: [], supported_platforms: ["windows"] };
  const readonly = { getSession: session("readonly"), createScript: async () => script };
  assert.equal((await handleScriptCreate(request("/api/scripts", body, "https://evil.test"), readonly)).status, 403);
  assert.equal((await handleScriptCreate(request("/api/scripts", body), readonly)).status, 403);
});

test("validated script creation uses the server session without exposing it", async () => {
  let token = ""; let input: unknown;
  const response = await handleScriptCreate(request("/api/scripts", { name: "Collect health", language: "powershell", content: "Get-Service", tags: ["diagnostic"], supported_platforms: ["windows"] }), {
    getSession: session("operator"), createScript: async (receivedToken, receivedInput) => { token = receivedToken; input = receivedInput; return { ...script, internal_secret: "sentinel" }; },
  });
  assert.equal(response.status, 201); assert.equal(token, "server-secret"); assert.deepEqual(input, { name: "Collect health", language: "powershell", content: "Get-Service", tags: ["diagnostic"], supported_platforms: ["windows"] });
  assert.doesNotMatch(JSON.stringify(await response.json()), /server-secret|internal_secret|sentinel/);
});

test("review and terminal deprecation require admins and bounded evidence", async () => {
  const reviewer = async () => script;
  assert.equal((await handleScriptReview(request("/review", { state: "approved", reason: "Reviewed safely" }), "script-1", 1, { getSession: session("operator"), review: reviewer })).status, 403);
  assert.equal((await handleScriptReview(request("/review", { state: "future", reason: "Reviewed safely" }), "script-1", 1, { getSession: session("admin"), review: reviewer })).status, 400);
  assert.equal((await handleScriptDeprecate(request("/deprecate", { expected_record_version: 1, request_id: "request-1234", reason: "Superseded" }), "script-1", { getSession: session("admin"), deprecate: async () => script })).status, 200);
});
