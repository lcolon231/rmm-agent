// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";
import { scriptItemFromUnknown, scriptListFromUnknown, scriptParameterValueSetFromUnknown, scriptState } from "../src/lib/script-library-core.ts";
import { handleScriptCreate, handleScriptDeprecate, handleScriptParameterValues, handleScriptReview } from "../src/lib/script-library-route-core.ts";

const version = { id: "version-1", version: 1, language: "powershell", content_sha256: "a".repeat(64), content_bytes: 11,
  description: "Collect health", tags: ["diagnostic"], supported_platforms: ["windows"], parameters: [], created_by: "operator@test", created_at: "2026-08-05T10:00:00Z", review: null };
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

test("parameter definitions and prepared-value evidence are allowlisted", async () => {
  const parameter = { key: "Token", label: "API token", description: null, kind: "secret",
    required: true, has_default: false, default_value: null, min_length: 8, max_length: 200,
    minimum: null, maximum: null, choices: null };
  const parsed = scriptItemFromUnknown({ ...script, latest: { ...version, parameters: [parameter] },
    versions: [{ ...version, parameters: [parameter] }] });
  assert.equal(parsed?.latest.parameters[0]?.kind, "secret");
  assert.equal(scriptItemFromUnknown({ ...script, latest: { ...version, parameters: [{ ...parameter, has_default: true }] } }), null);
  const evidence = { id: "set-1", script_id: "script-1", script_version_id: "version-1", version: 1,
    request_id: "request-1234", state: "available", provided_keys: ["Token"], defaulted_keys: [],
    secret_keys: ["Token"], values_fingerprint: "b".repeat(64), created_by: "operator@test",
    created_at: "2026-08-05T10:00:00Z", expires_at: "2026-08-06T10:00:00Z", secret: "sentinel" };
  assert.doesNotMatch(JSON.stringify(scriptParameterValueSetFromUnknown(evidence)), /sentinel|secret":/);
});

test("parameter preparation is same-origin, role-gated, and never reflects values", async () => {
  const body = { request_id: "request-1234", values: { Token: "top-secret" } };
  let received: unknown;
  const dependencies = { getSession: session("operator"), prepare: async (_token: string, _id: string, _version: number, _requestId: string, values: unknown) => {
    received = values; return { id: "set-1", script_id: "script-1", script_version_id: "version-1", version: 1,
      request_id: "request-1234", state: "available", provided_keys: ["Token"], defaulted_keys: [],
      secret_keys: ["Token"], values_fingerprint: "b".repeat(64), created_by: "operator@test",
      created_at: "2026-08-05T10:00:00Z", expires_at: "2026-08-06T10:00:00Z" }; } };
  assert.equal((await handleScriptParameterValues(request("/values", body, "https://evil.test"), "script-1", 1, dependencies)).status, 403);
  const response = await handleScriptParameterValues(request("/values", body), "script-1", 1, dependencies);
  assert.equal(response.status, 201); assert.deepEqual(received, { Token: "top-secret" });
  assert.doesNotMatch(JSON.stringify(await response.json()), /top-secret/);
  assert.equal((await handleScriptParameterValues(request("/values", body), "script-1", 1,
    { ...dependencies, getSession: session("readonly") })).status, 403);
});

test("expired and unavailable parameter states are surfaced, never invented", async () => {
  const evidence = { id: "set-1", script_id: "script-1", script_version_id: "version-1", version: 1,
    request_id: "request-1234", state: "expired", provided_keys: ["Token"], defaulted_keys: [],
    secret_keys: ["Token"], values_fingerprint: "b".repeat(64), created_by: "operator@test",
    created_at: "2026-08-05T10:00:00Z", expires_at: "2026-08-06T10:00:00Z" };
  // An expired set is still valid evidence; the state is carried through as-is.
  assert.equal(scriptParameterValueSetFromUnknown(evidence)?.state, "expired");
  // A state the server never emits must not be coerced into a usable one.
  assert.equal(scriptParameterValueSetFromUnknown({ ...evidence, state: "available_soon" }), null);
  assert.equal(scriptParameterValueSetFromUnknown({ ...evidence, values_fingerprint: "b".repeat(63) }), null);
  assert.equal(scriptParameterValueSetFromUnknown({ ...evidence, expires_at: "not-a-timestamp" }), null);

  const body = { request_id: "request-1234", values: { Token: "top-secret" } };
  // An unverifiable response is reported as unavailable rather than rendered.
  const malformed = await handleScriptParameterValues(request("/values", body), "script-1", 1,
    { getSession: session("operator"), prepare: async () => ({ ...evidence, state: "bogus" }) });
  assert.equal(malformed.status, 502);
  assert.doesNotMatch(JSON.stringify(await malformed.json()), /top-secret/);

  // A server-side failure (for example an absent encryption key) is not masked.
  const failed = await handleScriptParameterValues(request("/values", body), "script-1", 1,
    { getSession: session("operator"), prepare: async () => { throw new Error("parameter_encryption_unavailable"); } });
  assert.ok(failed.status >= 400);
  assert.doesNotMatch(JSON.stringify(await failed.json()), /top-secret/);

  // Malformed submissions are refused before any value reaches the server.
  let reached = false;
  const guard = { getSession: session("operator"), prepare: async () => { reached = true; return evidence; } };
  for (const invalid of [{ request_id: "short", values: {} }, { request_id: "request-1234", values: { Token: { nested: 1 } } },
    { request_id: "request-1234", values: { Token: "x" }, extra: 1 }]) {
    assert.equal((await handleScriptParameterValues(request("/values", invalid), "script-1", 1, guard)).status, 400);
  }
  assert.equal((await handleScriptParameterValues(request("/values", body), "script-1", 0, guard)).status, 400);
  assert.equal(reached, false);
});

test("review and terminal deprecation require admins and bounded evidence", async () => {
  const reviewer = async () => script;
  assert.equal((await handleScriptReview(request("/review", { state: "approved", reason: "Reviewed safely" }), "script-1", 1, { getSession: session("operator"), review: reviewer })).status, 403);
  assert.equal((await handleScriptReview(request("/review", { state: "future", reason: "Reviewed safely" }), "script-1", 1, { getSession: session("admin"), review: reviewer })).status, 400);
  assert.equal((await handleScriptDeprecate(request("/deprecate", { expected_record_version: 1, request_id: "request-1234", reason: "Superseded" }), "script-1", { getSession: session("admin"), deprecate: async () => script })).status, 200);
});
