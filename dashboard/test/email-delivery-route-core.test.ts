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

// --------------------------------------------------------------------------- //
// Coverage extension: sessions, malformed bodies, upstream mapping
// --------------------------------------------------------------------------- //
type EmailSession =
  | { kind: "anonymous" } | { kind: "unavailable" }
  | { kind: "authenticated"; operator: { role: "readonly" | "operator" | "admin" }; sessionToken: string };

test("email retry: no usable session never reaches the API", async () => {
  const sessions: Array<[number, () => Promise<EmailSession>]> = [
    [401, async () => ({ kind: "anonymous" })],
    [503, async () => ({ kind: "unavailable" })],
    [503, async () => { throw new Error("boom"); }],
  ];
  for (const [status, getSession] of sessions) {
    let calls = 0;
    const res = await handleEmailDeliveryRetry(request(), "delivery-1", {
      getSession, retryDelivery: async () => { calls += 1; return delivery; },
    });
    assert.equal(res.status, status);
    assert.equal(calls, 0);
  }
});

test("email retry: rejects non-object, missing, and non-string request ids", async () => {
  let calls = 0;
  const deps = {
    getSession: async (): Promise<EmailSession> => ({ kind: "authenticated", operator: { role: "operator" }, sessionToken: "t" }),
    retryDelivery: async () => { calls += 1; return delivery; },
  };
  for (const body of [null, {}, { request_id: 5 }, { request_id: "x".repeat(65) }, { request_id: "has space 0123456" }]) {
    assert.equal((await handleEmailDeliveryRetry(request(undefined, body), "delivery-1", deps)).status, 400);
  }
  const raw = new Request("https://dashboard.test/x", { method: "POST", headers: { Origin: "https://dashboard.test" }, body: "{bad" });
  assert.equal((await handleEmailDeliveryRetry(raw, "delivery-1", deps)).status, 400);
  assert.equal(calls, 0);
});

test("email retry: maps upstream failures and 502s on invalid evidence without leaking detail", async () => {
  const getSession = async (): Promise<EmailSession> => ({ kind: "authenticated", operator: { role: "operator" }, sessionToken: "server-secret" });
  const cases: Array<[unknown, number]> = [
    [{ status: 404 }, 404], [{ status: 409 }, 409], [{ status: 401 }, 401], [{ status: 403 }, 403],
    [{ status: 500 }, 503], [{}, 503], [null, 503], ["SENTINEL-string", 503],
  ];
  for (const [fields, expected] of cases) {
    const res = await handleEmailDeliveryRetry(request(), "delivery-1", {
      getSession,
      retryDelivery: async () => {
        throw fields && typeof fields === "object" ? Object.assign(new Error("SENTINEL-leak"), fields) : fields;
      },
    });
    assert.equal(res.status, expected);
    assert.doesNotMatch(JSON.stringify(await res.json()), /SENTINEL|server-secret/);
  }
  const bad = await handleEmailDeliveryRetry(request(), "delivery-1", {
    getSession, retryDelivery: async () => ({ junk: "SENTINEL" }),
  });
  assert.equal(bad.status, 502);
  assert.doesNotMatch(JSON.stringify(await bad.json()), /SENTINEL/);
});
