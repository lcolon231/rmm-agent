// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";
import { scriptItemFromUnknown, scriptListFromUnknown, scriptParameterValueSetFromUnknown, scriptState } from "../src/lib/script-library-core.ts";
import { handleScriptCreate, handleScriptDeprecate, handleScriptParameterValues, handleScriptReview, handleScriptVersionCreate } from "../src/lib/script-library-route-core.ts";

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

// --------------------------------------------------------------------------- //
// Coverage extension: shared behaviours across every script-library handler
// --------------------------------------------------------------------------- //
type SLRole = "readonly" | "operator" | "admin";
type SLSession =
  | { kind: "anonymous" } | { kind: "unavailable" }
  | { kind: "authenticated"; operator: { role: SLRole }; sessionToken: string };
const slSentinel = "SENTINEL-must-not-leak";
const versionBody = { language: "shell", content: "echo hi", tags: ["ops"], supported_platforms: ["linux"] };
const slValues = { request_id: "request-1234", values: { Name: "x" } };

type SLCase = {
  name: string; minRole: SLRole; body: unknown; upstream: unknown; successStatus: number; invalid: unknown;
  run: (req: Request, getSession: () => Promise<SLSession>, api: (...a: unknown[]) => Promise<unknown>) => Promise<Response>;
};
const slCases: SLCase[] = [
  {
    name: "create", minRole: "operator", body: { name: "S", ...versionBody }, invalid: { name: "", ...versionBody },
    upstream: { ...script, internal_secret: slSentinel }, successStatus: 201,
    run: (req, getSession, api) => handleScriptCreate(req, { getSession, createScript: api as never }),
  },
  {
    name: "version create", minRole: "operator", body: versionBody, invalid: { ...versionBody, language: "perl" },
    upstream: { ...script, internal_secret: slSentinel }, successStatus: 201,
    run: (req, getSession, api) => handleScriptVersionCreate(req, "script-1", { getSession, addVersion: api as never }),
  },
  {
    name: "review", minRole: "admin", body: { state: "approved", reason: "Reviewed safely" }, invalid: { state: "x", reason: "Reviewed safely" },
    upstream: { ...script, internal_secret: slSentinel }, successStatus: 200,
    run: (req, getSession, api) => handleScriptReview(req, "script-1", 1, { getSession, review: api as never }),
  },
  {
    name: "deprecate", minRole: "admin", body: { expected_record_version: 1, request_id: "request-1234", reason: "Superseded" },
    invalid: { expected_record_version: 0, request_id: "request-1234", reason: "Superseded" },
    upstream: { ...script, internal_secret: slSentinel }, successStatus: 200,
    run: (req, getSession, api) => handleScriptDeprecate(req, "script-1", { getSession, deprecate: api as never }),
  },
];

for (const c of slCases) {
  test(`script ${c.name}: no session never reaches the API`, async () => {
    const sessions: Array<[number, () => Promise<SLSession>]> = [
      [401, async () => ({ kind: "anonymous" })],
      [503, async () => ({ kind: "unavailable" })],
      [503, async () => { throw new Error("boom"); }],
    ];
    for (const [status, getSession] of sessions) {
      let calls = 0;
      const res = await c.run(request("/x", c.body), getSession, async () => { calls += 1; return c.upstream; });
      assert.equal(res.status, status);
      assert.equal(calls, 0);
    }
  });

  test(`script ${c.name}: cross-origin and under-privileged roles are rejected without forwarding`, async () => {
    let calls = 0;
    const api = async () => { calls += 1; return c.upstream; };
    assert.equal((await c.run(request("/x", c.body, "https://evil.test"), session("admin"), api)).status, 403);
    const roles: SLRole[] = c.minRole === "admin" ? ["readonly", "operator"] : ["readonly"];
    for (const role of roles) assert.equal((await c.run(request("/x", c.body), session(role), api)).status, 403);
    assert.equal(calls, 0);
  });

  test(`script ${c.name}: allowlists the response and maps upstream failures`, async () => {
    const ok = await c.run(request("/x", c.body), session("admin"), async () => c.upstream);
    assert.equal(ok.status, c.successStatus);
    assert.doesNotMatch(JSON.stringify(await ok.json()), /server-secret|internal_secret|SENTINEL/);
    const expected: Array<[number, number]> = [
      [401, 401], [403, 403], [404, 404], [409, 409], [413, 422], [422, 422], [500, 503], [502, 503],
    ];
    for (const [upstream, mapped] of expected) {
      const res = await c.run(request("/x", c.body), session("admin"), async () => {
        throw Object.assign(new Error(slSentinel), { status: upstream });
      });
      assert.equal(res.status, mapped);
      assert.doesNotMatch(JSON.stringify(await res.json()), /SENTINEL/);
    }
    assert.equal((await c.run(request("/x", c.body), session("admin"), async () => { throw new Error(slSentinel); })).status, 503);
    assert.equal((await c.run(request("/x", c.body), session("admin"), async () => ({ junk: slSentinel }))).status, 502);
  });

  test(`script ${c.name}: invalid bodies never reach the API`, async () => {
    let calls = 0;
    const api = async () => { calls += 1; return c.upstream; };
    assert.equal((await c.run(request("/x", c.invalid), session("admin"), api)).status, 400);
    assert.equal((await c.run(request("/x", [1]), session("admin"), api)).status, 400);
    const bad = new Request("https://dashboard.test/x", { method: "POST", headers: { Origin: "https://dashboard.test" }, body: "not json" });
    assert.equal((await c.run(bad, session("admin"), api)).status, 400);
    assert.equal(calls, 0);
  });
}

test("script version create forwards only the validated version input", async () => {
  let args: unknown[] = [];
  const res = await handleScriptVersionCreate(request("/x", { ...versionBody, description: "d", parameters: [
    { key: "Name", label: "Name", kind: "string", required: true, default_value: "a" },
  ] }), "script-9", {
    getSession: session("operator"), addVersion: async (...a) => { args = a; return script; },
  });
  assert.equal(res.status, 201);
  assert.equal(args[0], "server-secret");
  assert.equal(args[1], "script-9");
  // The version route does not accept a name; it would be an unknown key here.
  const named = await handleScriptVersionCreate(request("/x", { ...versionBody, name: "nope" }), "script-9", {
    getSession: session("operator"), addVersion: async () => script,
  });
  assert.equal(named.status, 400);
});

test("script version input validation rejects malformed metadata and parameters", async () => {
  const create = (patch: Record<string, unknown>) => handleScriptVersionCreate(
    request("/x", { ...versionBody, ...patch }), "script-1",
    { getSession: session("operator"), addVersion: async () => script },
  );
  assert.equal((await create({})).status, 201);
  for (const patch of [
    { content: "   " }, { content: "x".repeat(57_345) }, { description: 5 }, { tags: "ops" },
    { tags: ["bad tag!"] }, { tags: Array.from({ length: 21 }, (_, i) => `t${i}`) },
    { supported_platforms: [] }, { supported_platforms: ["beos"] }, { extra: 1 },
    { parameters: "x" }, { parameters: [1] },
    { parameters: Array.from({ length: 33 }, (_, i) => ({ key: `K${i}`, label: "L", kind: "string", required: false })) },
    { parameters: [{ key: "1bad", label: "L", kind: "string", required: false }] },
    { parameters: [{ key: "A", label: "L", kind: "string", required: false }, { key: "a", label: "L", kind: "string", required: false }] },
    { parameters: [{ key: "A", label: "", kind: "string", required: false }] },
    { parameters: [{ key: "A", label: "L", kind: "weird", required: false }] },
    { parameters: [{ key: "A", label: "L", kind: "string", required: "no" }] },
    { parameters: [{ key: "A", label: "L", kind: "string", required: false, extra: 1 }] },
    { parameters: [{ key: "A", label: "L", kind: "secret", required: false, default_value: "s" }] },
    { parameters: [{ key: "A", label: "L", kind: "choice", required: false }] },
    { parameters: [{ key: "A", label: "L", kind: "choice", required: false, choices: [] }] },
    { parameters: [{ key: "A", label: "L", kind: "string", required: false, default_value: 5 }] },
    { parameters: [{ key: "A", label: "L", kind: "number", required: false, default_value: "5" }] },
    { parameters: [{ key: "A", label: "L", kind: "boolean", required: false, default_value: "true" }] },
    { parameters: [{ key: "A", label: "L", kind: "string", required: false, description: "x".repeat(501) }] },
  ]) {
    assert.equal((await create(patch)).status, 400, JSON.stringify(patch).slice(0, 80));
  }
  for (const parameters of [
    [{ key: "A", label: "L", kind: "choice", required: true, choices: ["a", "b"] }],
    [{ key: "A", label: "L", kind: "number", required: false, default_value: 3 }],
    [{ key: "A", label: "L", kind: "boolean", required: false, default_value: true }],
    [{ key: "A", label: "L", kind: "secret", required: true }],
  ]) {
    assert.equal((await create({ parameters })).status, 201, JSON.stringify(parameters));
  }
});

test("script parameter values: role, session, and upstream mapping", async () => {
  let calls = 0;
  const api = async () => { calls += 1; return {}; };
  const run = (req: Request, getSession: () => Promise<SLSession>, prepare = api) =>
    handleScriptParameterValues(req, "script-1", 1, { getSession, prepare });
  assert.equal((await run(request("/x", slValues), async () => ({ kind: "anonymous" }))).status, 401);
  assert.equal((await run(request("/x", slValues), session("readonly"))).status, 403);
  assert.equal((await run(request("/x", slValues, "https://evil.test"), session("operator"))).status, 403);
  assert.equal(calls, 0);
  for (const [upstream, mapped] of [[404, 404], [409, 409], [422, 422], [500, 503]] as const) {
    const res = await run(request("/x", slValues), session("operator"), async () => {
      throw Object.assign(new Error(slSentinel), { status: upstream });
    });
    assert.equal(res.status, mapped);
  }
  assert.equal((await run(request("/x", slValues), session("operator"), async () => ({ junk: 1 }))).status, 502);
});
