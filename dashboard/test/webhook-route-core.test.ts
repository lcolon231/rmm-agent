// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";

import {
  handleWebhookDeliveryRetry,
  handleWebhookEndpointCreate,
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
