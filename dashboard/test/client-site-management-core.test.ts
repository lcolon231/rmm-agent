// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  clientRecordFromUnknown,
  describeClientSiteError,
  siteRecordFromUnknown,
  validateClientCreateInput,
  validateSiteCreateInput,
} from "../src/lib/client-site-management-core.ts";
import {
  handleCreateClient,
  handleCreateSite,
} from "../src/lib/client-site-management-route-core.ts";

const origin = "https://dashboard.example.test";
const sessionToken = "session-token-sentinel";

const managerSession = async () => ({
  kind: "authenticated" as const,
  operator: { role: "admin" as const },
  sessionToken,
});

function request(
  path: string,
  body: unknown,
  requestOrigin = origin,
): Request {
  return new Request(`${origin}${path}`, {
    body: JSON.stringify(body),
    headers: {
      "Content-Type": "application/json",
      Origin: requestOrigin,
    },
    method: "POST",
  });
}

test("validates and normalizes client and site names", () => {
  assert.deepEqual(
    validateClientCreateInput({ name: "  North Clinic  " }),
    { name: "North Clinic" },
  );
  assert.equal(validateClientCreateInput({ name: "   " }), null);
  assert.equal(validateClientCreateInput({ name: "x".repeat(201) }), null);
  assert.deepEqual(
    validateSiteCreateInput({
      client_id: " client-1 ",
      name: " Headquarters ",
    }),
    { client_id: "client-1", name: "Headquarters" },
  );
  assert.equal(
    validateSiteCreateInput({ client_id: "", name: "Headquarters" }),
    null,
  );
});

test("allowlists client and site responses", () => {
  const client = clientRecordFromUnknown({
    id: "client-1",
    name: "North Clinic",
    created_at: "2026-07-29T12:00:00Z",
    access_token: sessionToken,
  });
  const site = siteRecordFromUnknown({
    id: "site-1",
    client_id: "client-1",
    name: "Headquarters",
    created_at: "2026-07-29T12:01:00Z",
    password: "password-sentinel",
  });
  assert.ok(client);
  assert.ok(site);
  assert.doesNotMatch(JSON.stringify({ client, site }), /session-token|password-sentinel/);
});

test("maps duplicate and missing-parent states to actionable messages", () => {
  assert.deepEqual(
    describeClientSiteError("client", 409, "client_name_exists"),
    { message: "A client with this name already exists.", status: 409 },
  );
  assert.deepEqual(
    describeClientSiteError("site", 409, "site_name_exists"),
    {
      message: "A site with this name already exists under the selected client.",
      status: 409,
    },
  );
  assert.match(
    describeClientSiteError("site", 404, null).message,
    /selected client no longer exists/i,
  );
});

test("same-origin client creation forwards only the server-managed token", async () => {
  let calls = 0;
  const rejected = await handleCreateClient(
    request("/api/clients", { name: "North Clinic" }, "https://attacker.test"),
    {
      createClient: async () => {
        calls += 1;
        return {};
      },
      getSession: managerSession,
    },
  );
  assert.equal(rejected.status, 403);
  assert.equal(calls, 0);

  const accepted = await handleCreateClient(
    request("/api/clients", { name: " North Clinic " }),
    {
      createClient: async (token, input) => {
        assert.equal(token, sessionToken);
        assert.deepEqual(input, { name: "North Clinic" });
        return {
          id: "client-1",
          name: "North Clinic",
          created_at: "2026-07-29T12:00:00Z",
          access_token: sessionToken,
        };
      },
      getSession: managerSession,
    },
  );
  const text = await accepted.text();
  assert.equal(accepted.status, 201);
  assert.match(text, /North Clinic/);
  assert.doesNotMatch(text, new RegExp(sessionToken));
});

test("site creation preserves distinct 401, 403, 404, and 409 states", async () => {
  const anonymous = await handleCreateSite(
    request("/api/sites", { client_id: "client-1", name: "HQ" }),
    {
      createSite: async () => ({}),
      getSession: async () => ({ kind: "anonymous" as const }),
    },
  );
  assert.equal(anonymous.status, 401);

  const readonly = await handleCreateSite(
    request("/api/sites", { client_id: "client-1", name: "HQ" }),
    {
      createSite: async () => ({}),
      getSession: async () => ({
        kind: "authenticated" as const,
        operator: { role: "readonly" as const },
        sessionToken,
      }),
    },
  );
  assert.equal(readonly.status, 403);

  for (const [status, code, expected] of [
    [404, null, /selected client no longer exists/i],
    [409, "site_name_exists", /already exists under the selected client/i],
  ] as const) {
    const response = await handleCreateSite(
      request("/api/sites", { client_id: "client-1", name: "HQ" }),
      {
        createSite: async () => {
          throw { status, code, internal: "not-for-client" };
        },
        getSession: managerSession,
      },
    );
    const text = await response.text();
    assert.equal(response.status, status);
    assert.match(text, expected);
    assert.doesNotMatch(text, /not-for-client|internal/i);
  }
});


// --------------------------------------------------------------------------- //
// Coverage extension: shared session, role, validation, and mapping behaviour
// --------------------------------------------------------------------------- //
type CSSession =
  | { kind: "anonymous" } | { kind: "unavailable" }
  | { kind: "authenticated"; operator: { role: "readonly" | "operator" | "admin" }; sessionToken: string };
const csSentinel = "SENTINEL-must-not-leak";
const clientRecord = { id: "client-1", name: "North Clinic", created_at: "2026-07-29T12:00:00Z" };
const siteRecord = { id: "site-1", client_id: "client-1", name: "HQ", created_at: "2026-07-29T12:00:00Z" };

type CSCase = {
  name: string; path: string; body: unknown; invalid: unknown[]; ok: Record<string, unknown>; key: string;
  run: (req: Request, getSession: () => Promise<CSSession>, api: (...a: unknown[]) => Promise<unknown>) => Promise<Response>;
};
const csCases: CSCase[] = [
  {
    name: "client", path: "/api/clients", body: { name: "North Clinic" }, key: "client", ok: clientRecord,
    invalid: [{}, { name: "" }, { name: "   " }, { name: "x".repeat(201) }, { name: 5 }, null, "text"],
    run: (req, getSession, api) => handleCreateClient(req, { getSession, createClient: api as never }),
  },
  {
    name: "site", path: "/api/sites", body: { client_id: "client-1", name: "HQ" }, key: "site", ok: siteRecord,
    invalid: [{}, { name: "HQ" }, { client_id: "client-1" }, { client_id: "", name: "HQ" },
      { client_id: "c".repeat(37), name: "HQ" }, { client_id: 5, name: "HQ" }, { client_id: "client-1", name: " " }, null],
    run: (req, getSession, api) => handleCreateSite(req, { getSession, createSite: api as never }),
  },
];

for (const c of csCases) {
  test(`${c.name} creation: no usable session never reaches the API`, async () => {
    const sessions: Array<[number, () => Promise<CSSession>]> = [
      [401, async () => ({ kind: "anonymous" })],
      [503, async () => ({ kind: "unavailable" })],
      [503, async () => { throw new Error("boom"); }],
    ];
    for (const [status, getSession] of sessions) {
      let calls = 0;
      const res = await c.run(request(c.path, c.body), getSession, async () => { calls += 1; return c.ok; });
      assert.equal(res.status, status);
      assert.equal(calls, 0);
    }
  });

  test(`${c.name} creation: read-only role and cross-origin are rejected, operators allowed`, async () => {
    let calls = 0;
    const api = async () => { calls += 1; return { ...c.ok, access_token: csSentinel }; };
    const readonly = await c.run(request(c.path, c.body), async () => ({
      kind: "authenticated", operator: { role: "readonly" }, sessionToken,
    }), api);
    assert.equal(readonly.status, 403);
    assert.equal((await c.run(request(c.path, c.body, "https://evil.test"), managerSession, api)).status, 403);
    assert.equal(calls, 0);
    const operator = await c.run(request(c.path, c.body), async () => ({
      kind: "authenticated", operator: { role: "operator" }, sessionToken,
    }), api);
    assert.equal(operator.status, 201);
    const text = await operator.text();
    assert.doesNotMatch(text, new RegExp(`${csSentinel}|access_token|${sessionToken}`));
    assert.ok(JSON.parse(text)[c.key]);
  });

  test(`${c.name} creation: invalid bodies never reach the API`, async () => {
    let calls = 0;
    const api = async () => { calls += 1; return c.ok; };
    for (const body of c.invalid) {
      assert.equal((await c.run(request(c.path, body), managerSession, api)).status, 400, JSON.stringify(body));
    }
    const raw = new Request(`${origin}${c.path}`, { method: "POST", headers: { Origin: origin }, body: "{bad" });
    assert.equal((await c.run(raw, managerSession, api)).status, 400);
    assert.equal(calls, 0);
  });

  test(`${c.name} creation: maps upstream failures and rejects invalid evidence`, async () => {
    const expected: Array<[unknown, number]> = [
      [{ status: 401 }, 401], [{ status: 403 }, 403], [{ status: 404 }, c.name === "site" ? 404 : 503],
      [{ status: 409, code: "client_name_exists" }, 409], [{ status: 409, code: "site_name_exists" }, 409],
      [{ status: 400 }, 400], [{ status: 422 }, 400], [{ status: 500 }, 503], [{}, 503],
      [null, 503], [csSentinel, 503],
    ];
    for (const [thrown, mapped] of expected) {
      const res = await c.run(request(c.path, c.body), managerSession, async () => {
        throw thrown && typeof thrown === "object" ? Object.assign(new Error(csSentinel), thrown) : thrown;
      });
      assert.equal(res.status, mapped, JSON.stringify(thrown));
      assert.doesNotMatch(await res.text(), new RegExp(`${csSentinel}|${sessionToken}`));
    }
    const bad = await c.run(request(c.path, c.body), managerSession, async () => ({ junk: csSentinel }));
    assert.equal(bad.status, 502);
    assert.doesNotMatch(await bad.text(), new RegExp(csSentinel));
  });
}

test("site creation forwards a trimmed client id and name", async () => {
  let input: unknown;
  const res = await handleCreateSite(request("/api/sites", { client_id: " client-1 ", name: " HQ ", extra: "drop" }), {
    getSession: managerSession,
    createSite: async (_t, received) => { input = received; return siteRecord; },
  });
  assert.equal(res.status, 201);
  assert.deepEqual(input, { client_id: "client-1", name: "HQ" });
});
