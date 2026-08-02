// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  describeThreshold,
  formatCheckInterval,
  formatMonitoringScope,
  formatMonitoringTimestamp,
  monitoringPolicyDetailFromUnknown,
  monitoringPolicyListFromUnknown,
} from "../src/lib/monitoring-core.ts";

const check = {
  key: "cpu",
  type: "cpu",
  enabled: true,
  schedule: { interval_seconds: 60 },
  threshold: { op: "gte", warning: 80, critical: 95 },
  hysteresis: { raise_samples: 2, clear_samples: 3 },
  params: {},
};

const summary = {
  id: "policy-1",
  name: "Default health",
  scope: "global",
  scope_id: null,
  enabled: true,
  created_at: "2026-08-01T10:00:00Z",
  current_version: 2,
  check_count: 1,
};

test("policy lists are allowlisted and discard secret-adjacent fields", () => {
  const policies = monitoringPolicyListFromUnknown([
    { ...summary, access_token: "session-token-sentinel" },
  ]);
  assert.ok(policies);
  assert.equal(policies[0].name, "Default health");
  assert.doesNotMatch(JSON.stringify(policies), /session-token-sentinel|access_token/);
});

test("policy detail validates every nested check and revision", () => {
  const detail = monitoringPolicyDetailFromUnknown({
    ...summary,
    checks: [check],
    revisions: [
      {
        id: "revision-2",
        version: 2,
        change_note: "Tune CPU",
        created_by: "operator@nodelink.test",
        created_at: "2026-08-01T11:00:00Z",
        checks: [check],
        password: "password-sentinel",
      },
    ],
  });
  assert.ok(detail);
  assert.equal(detail.checks[0].threshold?.critical, 95);
  assert.equal(detail.revisions[0].version, 2);
  assert.doesNotMatch(JSON.stringify(detail), /password-sentinel|password/);

  assert.equal(
    monitoringPolicyDetailFromUnknown({
      ...summary,
      checks: [{ ...check, type: "future_check" }],
      revisions: [],
    }),
    null,
  );
});

test("offline checks are accepted as a supported monitoring contract", () => {
  const detail = monitoringPolicyDetailFromUnknown({
    ...summary,
    checks: [{ ...check, key: "offline", type: "offline" }],
    revisions: [],
  });
  assert.ok(detail);
  assert.equal(detail.checks[0].type, "offline");
});

test("scope, schedule, threshold, and timestamps format explicitly", () => {
  assert.equal(formatMonitoringScope("global"), "Global");
  assert.equal(formatMonitoringScope("agent"), "Agent");
  assert.equal(formatCheckInterval(60), "Every 1m");
  assert.equal(formatCheckInterval(7200), "Every 2h");
  assert.equal(formatCheckInterval(45), "Every 45s");
  assert.equal(
    describeThreshold({ op: "gte", warning: 80, critical: 95 }),
    "Warning â‰¥ 80 Â· Critical â‰¥ 95",
  );
  assert.equal(describeThreshold(null), "State check");
  assert.match(formatMonitoringTimestamp("2026-08-01T10:00:00Z"), /UTC/);
  assert.equal(formatMonitoringTimestamp("invalid"), "Unavailable");
});

test("scope identity consistency and malformed lists fail closed", () => {
  assert.equal(
    monitoringPolicyListFromUnknown([{ ...summary, scope: "site", scope_id: null }]),
    null,
  );
  assert.equal(monitoringPolicyListFromUnknown({ items: [] }), null);
  assert.equal(
    monitoringPolicyListFromUnknown([{ ...summary, check_count: -1 }]),
    null,
  );
});
