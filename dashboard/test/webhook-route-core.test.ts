// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";

import {
  handleWebhookDeliveryRetry,
  handleWebhookEndpointCreate,
  handleWebhookEndpointDelete,
  handleWebhookEndpointValidate,
  handleWebhookSecretRotate,
  handleWebhookEndpointUpdate,
} from "../src/lib/webhook-route-core.ts";

const endpoint = {
  id: "endpoint-1", name: "Incident relay", url: "https://*.example.test/…",
  event_types: ["opened", "automatic_recovery"], enabled: true,
  current_secret_version: 1, current_secret_key_id: "key-1", version: 1,
  deleted_at: null, created_at: "2026-08-05T10:00:00Z",
  updated_at: "2026-08-05T10:00:00Z",
};

function request(path: string, body: unknown, origin = "https://dashboard.test", method = "POST") {
  return new Request(`https://dashboard.test${path}`, {
    method,
    headers: { "Content-Type": "application/json", Origin: origin },
    body: JSON.stringify(body),
  });
}

test("webhook creation rejects cross-origin and non-admin requests", async () => {
  const readonly = {
    getSession: async () => ({
      kind: "authenticated" as const,
      operator: { role: "readonly" as const }, sessionToken: "server-secret",
    }),
    createEndpoint: async () => endpoint,
  };
  const body = {
    name: "Incident relay", url: "https://hooks.example.test/nodelink",
    event_types: ["opened"],
  };
  assert.equal((await handleWebhookEndpointCreate(
    request("/api/webhook-endpoints", body, "https://evil.test"), readonly,
  )).status, 403);
  assert.equal((await handleWebhookEndpointCreate(
    request("/api/webhook-endpoints", body), readonly,
  )).status, 403);
});

test("webhook creation forwards only validated input and allowlists the response", async () => {
  let token = "";
  let input: unknown;
  const response = await handleWebhookEndpointCreate(
    request("/api/webhook-endpoints", {
      name: "  Incident relay  ", url: "  https://hooks.example.test/nodelink  ",
      event_types: ["opened", "automatic_recovery"],
    }),
    {
      getSession: async () => ({
        kind: "authenticated" as const,
        operator: { role: "admin" as const }, sessionToken: "server-secret",
      }),
      createEndpoint: async (receivedToken, receivedInput) => {
        token = receivedToken;
        input = receivedInput;
        return {
          ...endpoint, secret: "whsec_once", signing_algorithm: "HMAC-SHA256",
          signature_header: "X-NodeLink-Signature", encrypted_secret: "must-not-leak",
        };
      },
    },
  );
  assert.equal(response.status, 201);
  assert.equal(token, "server-secret");
  assert.deepEqual(input, {
    name: "Incident relay", url: "https://hooks.example.test/nodelink",
    event_types: ["opened", "automatic_recovery"],
  });
  const serialized = JSON.stringify(await response.json());
  assert.match(serialized, /whsec_once/);
  assert.doesNotMatch(serialized, /server-secret|encrypted_secret|must-not-leak/);
});

test("webhook updates require bounded optimistic concurrency input", async () => {
  const dependencies = {
    getSession: async () => ({
      kind: "authenticated" as const,
      operator: { role: "admin" as const }, sessionToken: "server-secret",
    }),
    updateEndpoint: async () => endpoint,
  };
  const invalid = await handleWebhookEndpointUpdate(
    request("/api/webhook-endpoints/endpoint-1", {
      request_id: "short", expected_version: 0, enabled: false,
    }, undefined, "PUT"),
    "endpoint-1", dependencies,
  );
  assert.equal(invalid.status, 400);
});

test("webhook retry allows operators and never exposes the server session", async () => {
  const delivery = {
    id: "delivery-1", endpoint_id: "endpoint-1", endpoint_name: "Incident relay",
    alert_id: "alert-1", alert_event_id: "event-1", generation: 1,
    event_type: "opened", destination: "https://*.example.test/…", status: "retrying",
    attempt_count: 2, max_attempts: 3, next_attempt_at: "2026-08-05T10:02:00Z",
    last_http_status: 503, last_error_code: "http_503", delivered_at: null,
    created_at: "2026-08-05T10:00:00Z", updated_at: "2026-08-05T10:01:00Z",
    attempts: [],
  };
  let token = "";
  const response = await handleWebhookDeliveryRetry(
    request("/api/webhook-deliveries/delivery-1/retry", {
      request_id: "retry-request-1234",
    }),
    "delivery-1",
    {
      getSession: async () => ({
        kind: "authenticated" as const,
        operator: { role: "operator" as const }, sessionToken: "server-secret",
      }),
      retryDelivery: async (receivedToken) => {
        token = receivedToken;
        return { ...delivery, payload: "must-not-leak" };
      },
    },
  );
  assert.equal(response.status, 200);
  assert.equal(token, "server-secret");
  assert.doesNotMatch(JSON.stringify(await response.json()), /server-secret|payload|must-not-leak/);
});

type Role = "readonly" | "operator" | "admin";
type Session =
  | { kind: "anonymous" }
  | { kind: "unavailable" }
  | { kind: "authenticated"; operator: { role: Role }; sessionToken: string };

const validRid = "request-id-123456789";
const sentinel = "SENTINEL-must-not-leak";
const validation = {
  endpoint_id: "endpoint-1", state: "valid", code: null, resolved_address_count: 2,
};

function session(role: Role): () => Promise<Session> {
  return async () => ({ kind: "authenticated", operator: { role }, sessionToken: "server-secret" });
}

type Case = {
  name: string;
  minRole: Role;
  body: unknown;
  invalidBody?: unknown;
  upstream: unknown;
  run: (req: Request, getSession: () => Promise<Session>, api: (...args: unknown[]) => Promise<unknown>) => Promise<Response>;
};

const cases: Case[] = [
  {
    name: "validate", minRole: "operator", body: {}, upstream: { ...validation, secret: sentinel },
    run: (req, getSession, api) => handleWebhookEndpointValidate(req, "endpoint-1", {
      getSession, validateEndpoint: api as never,
    }),
  },
  {
    name: "rotate", minRole: "admin", body: { request_id: validRid, expected_version: 1 },
    invalidBody: { request_id: "x", expected_version: 1 },
    upstream: { ...endpoint, secret: "whsec_new", signing_algorithm: "HMAC-SHA256",
      signature_header: "X-NodeLink-Signature", encrypted_secret: sentinel },
    run: (req, getSession, api) => handleWebhookSecretRotate(req, "endpoint-1", {
      getSession, rotateSecret: api as never,
    }),
  },
  {
    name: "delete", minRole: "admin", body: { request_id: validRid, expected_version: 1 },
    invalidBody: { request_id: validRid, expected_version: 0 },
    upstream: { deleted: false, secret: sentinel },
    run: (req, getSession, api) => handleWebhookEndpointDelete(req, "endpoint-1", {
      getSession, deleteEndpoint: api as never,
    }),
  },
  {
    name: "retry", minRole: "operator", body: { request_id: validRid },
    invalidBody: { request_id: "x" },
    upstream: {
      id: "delivery-1", endpoint_id: "endpoint-1", endpoint_name: "Incident relay",
      alert_id: "alert-1", alert_event_id: "event-1", generation: 1, event_type: "opened",
      destination: "https://*.example.test/…", status: "retrying", attempt_count: 2,
      max_attempts: 3, next_attempt_at: "2026-08-05T10:02:00Z", last_http_status: 503,
      last_error_code: "http_503", delivered_at: null, created_at: "2026-08-05T10:00:00Z",
      updated_at: "2026-08-05T10:01:00Z", attempts: [], payload: sentinel,
    },
    run: (req, getSession, api) => handleWebhookDeliveryRetry(req, "delivery-1", {
      getSession, retryDelivery: api as never,
    }),
  },
  {
    name: "update", minRole: "admin", body: { request_id: validRid, expected_version: 1, enabled: false },
    invalidBody: { request_id: validRid, expected_version: 1 },
    upstream: { ...endpoint, encrypted_secret: sentinel },
    run: (req, getSession, api) => handleWebhookEndpointUpdate(req, "endpoint-1", {
      getSession, updateEndpoint: api as never,
    }),
  },
];

for (const c of cases) {
  test(`webhook ${c.name}: anonymous, unavailable, throwing sessions never reach the API`, async () => {
    const sessions: Array<[number, () => Promise<Session>]> = [
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

  test(`webhook ${c.name}: cross-origin and under-privileged roles are rejected without forwarding`, async () => {
    let calls = 0;
    const api = async () => { calls += 1; return c.upstream; };
    assert.equal((await c.run(request("/x", c.body, "https://evil.test"), session("admin"), api)).status, 403);
    const roles: Role[] = c.minRole === "admin" ? ["readonly", "operator"] : ["readonly"];
    for (const role of roles) {
      assert.equal((await c.run(request("/x", c.body), session(role), api)).status, 403);
    }
    assert.equal(calls, 0);
  });

  test(`webhook ${c.name}: maps upstream failures`, async () => {
    const expected: Array<[number, number]> = [
      [401, 401], [403, 403], [404, 404], [409, 409], [422, 422], [500, 503], [503, 503],
    ];
    for (const [upstream, mapped] of expected) {
      const res = await c.run(request("/x", c.body), session("admin"), async () => {
        throw Object.assign(new Error(sentinel), { status: upstream });
      });
      assert.equal(res.status, mapped);
      assert.doesNotMatch(JSON.stringify(await res.json()), new RegExp(sentinel));
    }
    const plain = await c.run(request("/x", c.body), session("admin"), async () => { throw new Error(sentinel); });
    assert.equal(plain.status, 503);
  });

  test(`webhook ${c.name}: success response is allowlisted`, async () => {
    let calls = 0;
    const res = await c.run(request("/x", c.body), session("admin"), async () => { calls += 1; return c.upstream; });
    assert.equal(res.status, 200);
    const text = JSON.stringify(await res.json());
    assert.doesNotMatch(text, new RegExp(`${sentinel}|server-secret`));
    if (c.name === "delete") assert.equal(text, JSON.stringify({ deleted: true }));
    assert.equal(calls, 1);
  });

  if (c.invalidBody !== undefined) {
    test(`webhook ${c.name}: invalid bodies are rejected with 400`, async () => {
      let calls = 0;
      const api = async () => { calls += 1; return c.upstream; };
      assert.equal((await c.run(request("/x", c.invalidBody), session("admin"), api)).status, 400);
      const bad = new Request("https://dashboard.test/x", {
        method: "POST", headers: { Origin: "https://dashboard.test" }, body: "not json",
      });
      assert.equal((await c.run(bad, session("admin"), api)).status, 400);
      assert.equal(calls, 0);
    });
  }
}

test("webhook handlers return 502 for malformed upstream payloads", async () => {
  const v = await handleWebhookEndpointValidate(request("/x", {}), "endpoint-1", {
    getSession: session("operator"), validateEndpoint: async () => ({ nope: sentinel }),
  });
  assert.equal(v.status, 502);
  const r = await handleWebhookSecretRotate(request("/x", { request_id: validRid, expected_version: 2 }), "endpoint-1", {
    getSession: session("admin"), rotateSecret: async () => ({ nope: sentinel }),
  });
  assert.equal(r.status, 502);
  const u = await handleWebhookEndpointUpdate(
    request("/x", { request_id: validRid, expected_version: 2, enabled: true }), "endpoint-1",
    { getSession: session("admin"), updateEndpoint: async () => null },
  );
  assert.equal(u.status, 502);
  const d = await handleWebhookDeliveryRetry(request("/x", { request_id: validRid }), "d", {
    getSession: session("operator"), retryDelivery: async () => null,
  });
  assert.equal(d.status, 502);
  const c = await handleWebhookEndpointCreate(
    request("/x", { name: "n", url: "https://h.example.test", event_types: ["opened"] }),
    { getSession: session("admin"), createEndpoint: async () => null },
  );
  assert.equal(c.status, 502);
});

test("webhook rotate and delete forward ids, request id, and version; validate reports evidence", async () => {
  let rotateArgs: unknown[] = [];
  await handleWebhookSecretRotate(request("/x", { request_id: validRid, expected_version: 3 }), "endpoint-9", {
    getSession: session("admin"),
    rotateSecret: async (...args) => { rotateArgs = args; return endpoint; },
  });
  assert.deepEqual(rotateArgs, ["server-secret", "endpoint-9", validRid, 3]);
  let deleteArgs: unknown[] = [];
  await handleWebhookEndpointDelete(request("/x", { request_id: validRid, expected_version: 4 }, undefined, "DELETE"), "endpoint-9", {
    getSession: session("admin"),
    deleteEndpoint: async (...args) => { deleteArgs = args; return undefined; },
  });
  assert.deepEqual(deleteArgs, ["server-secret", "endpoint-9", validRid, 4]);
  const res = await handleWebhookEndpointValidate(request("/x", {}), "endpoint-9", {
    getSession: session("operator"), validateEndpoint: async () => validation,
  });
  assert.deepEqual(await res.json(), { validation });
});

test("webhook create and update reject unknown keys, bad event types, and empty updates", async () => {
  const create = (body: unknown) => handleWebhookEndpointCreate(request("/x", body), {
    getSession: session("admin"), createEndpoint: async () => endpoint,
  });
  const base = { name: "n", url: "https://h.example.test", event_types: ["opened"] };
  assert.equal((await create({ ...base, extra: 1 })).status, 400);
  assert.equal((await create({ ...base, event_types: ["opened", "opened"] })).status, 400);
  assert.equal((await create({ ...base, event_types: ["bogus"] })).status, 400);
  assert.equal((await create({ ...base, name: " " })).status, 400);
  assert.equal((await create({ ...base, url: 5 })).status, 400);
  const update = (body: unknown) => handleWebhookEndpointUpdate(request("/x", body, undefined, "PUT"), "endpoint-1", {
    getSession: session("admin"), updateEndpoint: async () => endpoint,
  });
  const ub = { request_id: validRid, expected_version: 1 };
  assert.equal((await update({ ...ub, extra: 1, enabled: true })).status, 400);
  assert.equal((await update({ ...ub, name: "" })).status, 400);
  assert.equal((await update({ ...ub, url: "" })).status, 400);
  assert.equal((await update({ ...ub, event_types: [] })).status, 400);
  assert.equal((await update({ ...ub, enabled: "yes" })).status, 400);
  let input: unknown;
  const ok = await handleWebhookEndpointUpdate(
    request("/x", { ...ub, name: " A ", url: " https://h.example.test ", event_types: ["opened"], enabled: true }, undefined, "PUT"),
    "endpoint-1",
    { getSession: session("admin"), updateEndpoint: async (_t, _i, i) => { input = i; return endpoint; } },
  );
  assert.equal(ok.status, 200);
  assert.deepEqual(input, { ...ub, name: "A", url: "https://h.example.test", event_types: ["opened"], enabled: true });
});
