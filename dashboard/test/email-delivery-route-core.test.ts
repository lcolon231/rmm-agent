// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";
import { handleEmailDeliveryRetry } from "../src/lib/email-delivery-route-core.ts";

const delivery = {
  id: "delivery-1", alert_id: "alert-1", alert_event_id: "event-1",
  generation: 1, event_type: "opened", recipient: "f***@example.test",
  status: "retrying", attempt_count: 3, max_attempts: 4,
  next_attempt_at: "2026-08-04T10:00:00Z", provider_message_id: null,
  last_error_code: "rate_limited", sent_at: null,
  created_at: "2026-08-04T09:00:00Z", updated_at: "2026-08-04T10:00:00Z",
  attempts: [],
};

function request(origin = "https://dashboard.test", body: unknown = {
  request_id: "retry-request-1234",
}) {
  return new Request("https://dashboard.test/api/email-deliveries/delivery-1/retry", {
    method: "POST", headers: { "Content-Type": "application/json", Origin: origin },
    body: JSON.stringify(body),
  });
}

test("email retry route rejects cross-origin and read-only requests", async () => {
  const dependencies = {
    getSession: async () => ({
      kind: "authenticated" as const,
      operator: { role: "readonly" as const }, sessionToken: "server-secret",
    }),
    retryDelivery: async () => delivery,
  };
  assert.equal((await handleEmailDeliveryRetry(
    request("https://evil.test"), "delivery-1", dependencies,
  )).status, 403);
  assert.equal((await handleEmailDeliveryRetry(
    request(), "delivery-1", dependencies,
  )).status, 403);
});

test("email retry route validates and forwards only the server session", async () => {
  let token = "";
  let requestId = "";
  const response = await handleEmailDeliveryRetry(request(), "delivery-1", {
    getSession: async () => ({
      kind: "authenticated" as const,
      operator: { role: "operator" as const }, sessionToken: "server-secret",
    }),
    retryDelivery: async (receivedToken, _deliveryId, receivedRequestId) => {
      token = receivedToken;
      requestId = receivedRequestId;
      return { ...delivery, api_key: "must-not-leak" };
    },
  });
  assert.equal(response.status, 200);
  assert.equal(token, "server-secret");
  assert.equal(requestId, "retry-request-1234");
  assert.doesNotMatch(JSON.stringify(await response.json()), /server-secret|api_key|must-not-leak/);
});

test("email retry route rejects malformed idempotency keys", async () => {
  const response = await handleEmailDeliveryRetry(request(undefined, {
    request_id: "short",
  }), "delivery-1", {
    getSession: async () => ({
      kind: "authenticated" as const,
      operator: { role: "admin" as const }, sessionToken: "token",
    }),
    retryDelivery: async () => delivery,
  });
  assert.equal(response.status, 400);
});
