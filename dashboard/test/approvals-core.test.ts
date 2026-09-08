// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";

import {
  approvalPolicyFromUnknown,
  approvalRequestDetailFromUnknown,
  approvalRequestFromUnknown,
  approvalRequestListFromUnknown,
  canDecide,
  decideBlockedReason,
  formatApprovalScope,
  formatTimeRemaining,
  isValidDecisionReason,
  sortForReview,
  statusLabel,
  type ApprovalRequest,
  type ApprovalRequestDetail,
} from "../src/lib/approvals-core.ts";

const REQUEST = {
  id: "req-1",
  agent_id: "agent-1",
  client_id: "client-1",
  site_id: "site-1",
  kind: "powershell",
  status: "pending",
  payload_sha256: "a".repeat(64),
  policy_id: "policy-1",
  required_approvals: 2,
  approvals_recorded: 0,
  requested_by_email: "req@example.test",
  requested_by_operator_id: "op-req",
  reason: "Spooler wedged, INC-4711",
  created_at: "2026-09-02T10:00:00Z",
  expires_at: "2026-09-02T11:00:00Z",
  decided_at: null,
  consumed_at: null,
};

const DETAIL = {
  ...REQUEST,
  payload: { script: "Restart-Service -Name Spooler" },
  payload_keys: ["script"],
  decisions: [
    {
      id: "dec-1",
      operator_id: "op-a",
      operator_email: "a@example.test",
      operator_role: "operator",
      decision: "approve",
      reason: "Change window confirmed",
      created_at: "2026-09-02T10:05:00Z",
    },
  ],
  closed_at: null,
  closed_by_email: null,
  closed_reason: null,
  consumed_command_id: null,
};

test("a well-formed request parses", () => {
  const parsed = approvalRequestFromUnknown(REQUEST);
  assert.ok(parsed);
  assert.equal(parsed.kind, "powershell");
  assert.equal(parsed.required_approvals, 2);
});

test("parsers fail closed on unexpected shapes", () => {
  assert.equal(approvalRequestFromUnknown(null), null);
  assert.equal(approvalRequestFromUnknown({ ...REQUEST, status: "invented" }), null);
  assert.equal(approvalRequestFromUnknown({ ...REQUEST, required_approvals: "2" }), null);
  assert.equal(approvalRequestFromUnknown({ ...REQUEST, client_id: 7 }), null);
  assert.equal(approvalRequestListFromUnknown([REQUEST, { bogus: true }]), null);
  assert.equal(approvalPolicyFromUnknown({ id: "p", name: "n", scope: "nowhere" }), null);
  assert.equal(
    approvalRequestDetailFromUnknown({ ...DETAIL, decisions: [{ id: "x" }] }),
    null,
  );
});

test("a policy parses and reports its scope", () => {
  const policy = approvalPolicyFromUnknown({
    id: "policy-1",
    name: "Dual control",
    scope: "client",
    scope_id: "client-abcdef12",
    command_kinds: ["powershell"],
    required_approvals: 2,
    request_ttl_seconds: 3600,
    enabled: true,
    created_at: "2026-09-02T09:00:00Z",
    created_by: "admin@example.test",
    updated_at: null,
    updated_by: null,
  });
  assert.ok(policy);
  assert.equal(formatApprovalScope(policy.scope, policy.scope_id), "Client client-a");
  assert.equal(formatApprovalScope("global", null), "All tenants");
});

test("the requester can never decide their own request", () => {
  const detail = approvalRequestDetailFromUnknown(DETAIL) as ApprovalRequestDetail;
  assert.equal(canDecide(detail, "op-req"), false);
  assert.match(decideBlockedReason(detail, "op-req") ?? "", /you raised this request/i);
});

test("an identity that already voted cannot vote again", () => {
  const detail = approvalRequestDetailFromUnknown(DETAIL) as ApprovalRequestDetail;
  assert.equal(canDecide(detail, "op-a"), false);
  assert.match(decideBlockedReason(detail, "op-a") ?? "", /already recorded/i);
  assert.equal(canDecide(detail, "op-b"), true);
  assert.equal(decideBlockedReason(detail, "op-b"), null);
});

test("only a pending request is decidable", () => {
  const approved = approvalRequestDetailFromUnknown({
    ...DETAIL,
    status: "approved",
  }) as ApprovalRequestDetail;
  assert.equal(canDecide(approved, "op-b"), false);
  assert.match(decideBlockedReason(approved, "op-b") ?? "", /approved/i);
});

test("an unresolved viewer identity cannot decide", () => {
  const detail = approvalRequestDetailFromUnknown(DETAIL) as ApprovalRequestDetail;
  assert.equal(canDecide(detail, null), false);
});

test("reason validation mirrors the server bounds", () => {
  assert.equal(isValidDecisionReason("too short"), false);
  assert.equal(isValidDecisionReason(""), false);
  assert.equal(isValidDecisionReason("x".repeat(513)), false);
  assert.equal(isValidDecisionReason("Change window confirmed"), true);
  assert.equal(isValidDecisionReason(`bad${String.fromCharCode(7)}control character`), false);
  assert.equal(isValidDecisionReason("   Change window confirmed   "), true);
});

test("the queue puts actionable work first, then the most urgent", () => {
  const rows: ApprovalRequest[] = [
    { ...REQUEST, id: "consumed", status: "consumed" } as ApprovalRequest,
    {
      ...REQUEST,
      id: "pending-late",
      expires_at: "2026-09-02T12:00:00Z",
    } as ApprovalRequest,
    { ...REQUEST, id: "approved", status: "approved" } as ApprovalRequest,
    { ...REQUEST, id: "pending-soon" } as ApprovalRequest,
  ];
  assert.deepEqual(
    sortForReview(rows).map((row) => row.id),
    ["pending-soon", "pending-late", "approved", "consumed"],
  );
});

test("status labels read as an outcome, not an enum", () => {
  assert.equal(statusLabel("pending"), "Awaiting approval");
  assert.equal(statusLabel("consumed"), "Executed");
});

test("remaining time is rendered for a reviewer deciding whether to act", () => {
  const now = new Date("2026-09-02T10:00:00Z");
  assert.equal(formatTimeRemaining("2026-09-02T10:30:00Z", now), "30 min left");
  assert.equal(formatTimeRemaining("2026-09-03T10:00:00Z", now), "24 h left");
  assert.equal(formatTimeRemaining("2026-09-09T10:00:00Z", now), "7 d left");
  assert.equal(formatTimeRemaining("2026-09-02T09:00:00Z", now), "expired");
  assert.equal(formatTimeRemaining("not a date", now), "unknown");
});
