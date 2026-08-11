// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  formatComplianceState,
  listFromUnknown,
  summaryFromUnknown,
} from "../src/lib/patch-compliance-core.ts";

const summary = {
  total_endpoints: 8,
  compliant: 3,
  non_compliant: 2,
  stale: 1,
  unknown: 1,
  exempt: 1,
  total_approved_missing: 7,
  truncated: false,
  internal_note: "must not escape",
};

const endpoint = {
  agent_id: "agent-1",
  hostname: "WS-001",
  site_id: "site-1",
  site_name: "HQ",
  client_id: "client-1",
  client_name: "Acme",
  state: "non_compliant",
  policy_id: "policy-1",
  scanned_at: "2026-08-11T12:00:00Z",
  total_missing: 4,
  approved_missing: 2,
  deferred_missing: 1,
  denied_missing: 1,
  secret: "must not escape",
};

test("summary parser allowlists validated fields", () => {
  assert.deepEqual(summaryFromUnknown(summary), {
    total_endpoints: 8,
    compliant: 3,
    non_compliant: 2,
    stale: 1,
    unknown: 1,
    exempt: 1,
    total_approved_missing: 7,
    truncated: false,
  });
});

test("summary parser fails closed", () => {
  assert.equal(summaryFromUnknown({ ...summary, compliant: -1 }), null);
  assert.equal(summaryFromUnknown({ ...summary, truncated: "false" }), null);
  assert.equal(summaryFromUnknown(null), null);
});

test("list parser allowlists endpoint and pagination fields", () => {
  assert.deepEqual(
    listFromUnknown({ items: [endpoint], page: 1, page_size: 25, total: 1, truncated: false }),
    {
      items: [{
        agent_id: "agent-1",
        hostname: "WS-001",
        site_id: "site-1",
        site_name: "HQ",
        client_id: "client-1",
        client_name: "Acme",
        state: "non_compliant",
        policy_id: "policy-1",
        scanned_at: "2026-08-11T12:00:00Z",
        total_missing: 4,
        approved_missing: 2,
        deferred_missing: 1,
        denied_missing: 1,
      }],
      page: 1,
      page_size: 25,
      total: 1,
      truncated: false,
    },
  );
});

test("list parser fails closed on invalid state, timestamp, count, or paging", () => {
  const list = (item: unknown, overrides = {}) => ({
    items: [item], page: 1, page_size: 25, total: 1, truncated: false, ...overrides,
  });
  assert.equal(listFromUnknown(list({ ...endpoint, state: "pending" })), null);
  assert.equal(listFromUnknown(list({ ...endpoint, scanned_at: "yesterday" })), null);
  assert.equal(listFromUnknown(list({ ...endpoint, approved_missing: -1 })), null);
  assert.equal(listFromUnknown(list(endpoint, { page_size: 101 })), null);
});

test("state formatter uses operator-facing labels", () => {
  assert.equal(formatComplianceState("compliant"), "Compliant");
  assert.equal(formatComplianceState("non_compliant"), "Non-compliant");
  assert.equal(formatComplianceState("stale"), "Stale");
  assert.equal(formatComplianceState("unknown"), "Unknown");
  assert.equal(formatComplianceState("exempt"), "Exempt");
});
