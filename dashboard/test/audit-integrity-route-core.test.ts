// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  formatAnchorTime,
  handleAuditIntegrity,
  integrityFromUnknown,
  summarizeIntegrity,
} from "../src/lib/audit-integrity-core.ts";
import { SENTINEL, bffContract, request, sessionFor } from "./bff-contract.ts";

bffContract([
  {
    name: "audit integrity",
    minRole: "readonly",
    mutation: false,
    upstreamResult: {
      verification: { intact: true, first_broken_event_id: SENTINEL, extra: SENTINEL },
      anchors: [{ id: SENTINEL, created_at: "2026-11-11T09:40:00Z", merkle_root: SENTINEL }],
    },
    invoke: ({ getSession, call }) =>
      handleAuditIntegrity(request("/api/audit/integrity"), {
        getSession,
        getIntegrityInputs: call as never,
      }),
  },
]);

test("intact is reported only from a successful verification", () => {
  assert.equal(summarizeIntegrity({ verification: { intact: true }, anchors: [] }).chain, "intact");
  assert.equal(summarizeIntegrity({ verification: { intact: false, first_broken_event_id: "e1" }, anchors: [] }).chain, "failed");
  for (const verification of [null, undefined, {}, { intact: "true" }, { intact: 1 }, "intact", []]) {
    assert.equal(summarizeIntegrity({ verification, anchors: [] }).chain, "unknown", JSON.stringify(verification));
  }
});

test("the newest readable anchor wins, regardless of order", () => {
  const summary = summarizeIntegrity({
    verification: { intact: true },
    anchors: [
      { created_at: "2026-11-10T08:00:00Z" },
      { created_at: "not a date" },
      { created_at: "2026-11-11T09:40:00Z" },
      { created_at: 7 },
      null,
      { created_at: "2026-11-09T23:00:00Z" },
    ],
  });
  assert.equal(summary.last_anchor_at, "2026-11-11T09:40:00.000Z");
  assert.equal(summarizeIntegrity({ verification: { intact: true }, anchors: null }).last_anchor_at, null);
});

test("an unreachable check answers unknown with 200, so the shell never breaks", async () => {
  const response = await handleAuditIntegrity(request("/api/audit/integrity"), {
    getSession: sessionFor("readonly"),
    getIntegrityInputs: async () => {
      throw new Error("upstream down");
    },
  });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { chain: "unknown", last_anchor_at: null });
});

test("the client parser never upgrades an unexpected answer to intact", () => {
  assert.deepEqual(integrityFromUnknown({ chain: "intact", last_anchor_at: "2026-11-11T09:40:00Z" }), {
    chain: "intact",
    last_anchor_at: "2026-11-11T09:40:00Z",
  });
  for (const value of [null, "intact", { chain: "INTACT" }, { chain: true }, { error: "Sign in" }]) {
    assert.equal(integrityFromUnknown(value).chain, "unknown", JSON.stringify(value));
  }
  assert.equal(integrityFromUnknown({ chain: "failed", last_anchor_at: "garbage" }).last_anchor_at, null);
});

test("anchor times read as today, yesterday, or a date", () => {
  const now = new Date(2026, 10, 11, 15, 0);
  assert.equal(formatAnchorTime(new Date(2026, 10, 11, 9, 40).toISOString(), now), "today, 09:40");
  assert.equal(formatAnchorTime(new Date(2026, 10, 10, 17, 5).toISOString(), now), "yesterday, 17:05");
  assert.equal(formatAnchorTime(new Date(2026, 10, 3, 9, 40).toISOString(), now), "3 Nov 2026, 09:40");
});
