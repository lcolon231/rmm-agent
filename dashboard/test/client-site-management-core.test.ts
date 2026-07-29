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
