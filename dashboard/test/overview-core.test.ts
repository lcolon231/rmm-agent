// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";

import type { ApprovalRequest } from "../src/lib/approvals-core.ts";
import type { AuditEventRecord } from "../src/lib/audit-core.ts";
import type { MonitoringAlert } from "../src/lib/monitoring-core.ts";
import {
  compliancePercent,
  formatRequestKind,
  openAlertsBySeverity,
  recentActivity,
  waitingForApproval,
} from "../src/lib/overview-core.ts";

const now = new Date("2026-11-11T12:00:00Z");

test("open alerts by severity ignore resolved alerts and add up to the total", () => {
  const alerts = [
    { state: "open", last_result_status: "critical" },
    { state: "acknowledged", last_result_status: "warning" },
    { state: "open", last_result_status: "unknown" },
    { state: "open", last_result_status: "ok" },
    { state: "resolved", last_result_status: "critical" },
  ] as MonitoringAlert[];
  const result = openAlertsBySeverity(alerts);
  assert.equal(result.total, 4);
  assert.deepEqual(result.rows.map((row) => [row.label, row.count]), [["Critical", 1], ["Warning", 1], ["Notice", 2]]);
  assert.equal(result.rows.reduce((sum, row) => sum + row.count, 0), result.total);
});

test("compliance leaves exempt devices out and never shows a percent for an empty scope", () => {
  const base = { non_compliant: 0, stale: 0, unknown: 0, total_approved_missing: 0, truncated: false };
  assert.deepEqual(compliancePercent({ ...base, total_endpoints: 42, compliant: 38, exempt: 2 }), { percent: 95, compliant: 38, inScope: 40 });
  assert.equal(compliancePercent({ ...base, total_endpoints: 3, compliant: 2, exempt: 0 })?.percent, 66, "rounds down: 66.7% is not shown as meeting 67%");
  assert.equal(compliancePercent({ ...base, total_endpoints: 2, compliant: 0, exempt: 2 }), null);
});

function request(overrides: Partial<ApprovalRequest>): ApprovalRequest {
  return {
    id: "r",
    agent_id: "a",
    client_id: null,
    site_id: null,
    kind: "script_run",
    status: "pending",
    payload_sha256: "x",
    policy_id: null,
    required_approvals: 1,
    approvals_recorded: 0,
    requested_by_email: "tech@clinic.example",
    requested_by_operator_id: "someone-else",
    reason: "",
    created_at: "2026-11-11T11:00:00Z",
    expires_at: "2026-11-11T13:00:00Z",
    decided_at: null,
    consumed_at: null,
    ...overrides,
  };
}

test("an operator is never asked to approve their own request, or an expired or decided one", () => {
  const list = waitingForApproval(
    [
      request({ id: "later", expires_at: "2026-11-11T15:00:00Z" }),
      request({ id: "mine", requested_by_operator_id: "me" }),
      request({ id: "expired", expires_at: "2026-11-11T11:59:00Z" }),
      request({ id: "approved", status: "approved" }),
      request({ id: "soonest", expires_at: "2026-11-11T12:30:00Z" }),
    ],
    "me",
    now,
  );
  assert.deepEqual(list.map((entry) => entry.id), ["soonest", "later"]);
});

test("request kinds read as sentence case", () => {
  assert.equal(formatRequestKind("script_run"), "Script run");
  assert.equal(formatRequestKind("power.restart"), "Power restart");
  assert.equal(formatRequestKind(""), "Request");
});

test("recent activity is newest first and names devices by hostname when known", () => {
  const events = [
    { id: "1", ts: "2026-11-11T10:00:00Z", actor: "a@x", action: "command.dispatched", agent_id: "agent-known-1234" },
    { id: "2", ts: "2026-11-11T11:00:00Z", actor: "", action: "audit.anchored", agent_id: null },
    { id: "3", ts: "2026-11-11T09:00:00Z", actor: "b@x", action: "agent_revoked", agent_id: "deadbeefcafe" },
  ] as AuditEventRecord[];
  const rows = recentActivity(events, new Map([["agent-known-1234", "PHX-FD-02"]]));
  assert.deepEqual(
    rows.map((row) => [row.id, row.actor, row.verb, row.target]),
    [
      ["2", "System", "audit anchored", null],
      ["1", "a@x", "command dispatched", "PHX-FD-02"],
      ["3", "b@x", "agent revoked", "device deadbeef"],
    ],
  );
});
