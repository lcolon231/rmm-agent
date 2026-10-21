// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";

import {
  canReview,
  canRevoke,
  canRun,
  emergencyOverrideDetailFromUnknown,
  emergencyOverrideFromUnknown,
  emergencyOverrideListFromUnknown,
  formatTimeRemaining,
  isValidJustification,
  isValidNote,
  isValidTtlSeconds,
  notificationLabel,
  parsePayloadText,
  sortForReview,
  statusLabel,
  type EmergencyOverride,
} from "../src/lib/emergency-overrides-core.ts";

const NOW = new Date("2026-10-21T10:00:00Z");

const OVERRIDE: EmergencyOverride = {
  id: "ovr-1",
  agent_id: "agent-1",
  client_id: "client-1",
  site_id: "site-1",
  kind: "powershell",
  status: "active",
  payload_sha256: "a".repeat(64),
  policy_id: "policy-1",
  required_approvals: 2,
  activated_by_email: "admin@example.test",
  activated_by_operator_id: "op-admin",
  justification: "Print server down for 40 users, INC-9001, approvers unreachable",
  created_at: "2026-10-21T09:55:00Z",
  expires_at: "2026-10-21T10:10:00Z",
  consumed_at: null,
  revoked_at: null,
  revoked_by_email: null,
  notified_at: "2026-10-21T09:55:01Z",
  notification_error: null,
  notified_recipient_count: 2,
  reviewed_at: null,
  reviewed_by_email: null,
};

test("summary parser accepts the service shape and rejects drift", () => {
  assert.deepEqual(emergencyOverrideFromUnknown(OVERRIDE), OVERRIDE);
  assert.equal(emergencyOverrideFromUnknown({ ...OVERRIDE, status: "pending" }), null);
  assert.equal(emergencyOverrideFromUnknown({ ...OVERRIDE, notified_recipient_count: "2" }), null);
  assert.equal(emergencyOverrideFromUnknown({ ...OVERRIDE, reviewed_at: 5 }), null);
  assert.equal(emergencyOverrideFromUnknown(null), null);
  assert.equal(emergencyOverrideFromUnknown([OVERRIDE]), null);
});

test("list parser fails closed on one bad row", () => {
  assert.deepEqual(emergencyOverrideListFromUnknown([OVERRIDE]), [OVERRIDE]);
  assert.equal(emergencyOverrideListFromUnknown([OVERRIDE, { id: "x" }]), null);
  assert.equal(emergencyOverrideListFromUnknown("nope"), null);
});

test("detail parser requires payload, keys, and the review fields", () => {
  const detail = {
    ...OVERRIDE,
    payload: { script: "Restart-Service -Name Spooler" },
    payload_keys: ["script"],
    revoke_reason: null,
    review_note: null,
    consumed_command_id: null,
  };
  assert.deepEqual(emergencyOverrideDetailFromUnknown(detail), detail);
  assert.equal(emergencyOverrideDetailFromUnknown({ ...detail, payload: [] }), null);
  assert.equal(emergencyOverrideDetailFromUnknown({ ...detail, payload_keys: [1] }), null);
  assert.equal(emergencyOverrideDetailFromUnknown({ ...detail, consumed_command_id: 7 }), null);
});

test("justification and note bounds mirror the service", () => {
  assert.equal(isValidJustification("too short"), false);
  assert.equal(isValidJustification(OVERRIDE.justification), true);
  assert.equal(isValidJustification("x".repeat(513)), false);
  assert.equal(isValidJustification("contains a tab\there and is long enough"), false);
  assert.equal(isValidNote("short"), false);
  assert.equal(isValidNote("Checked the ticket, warranted"), true);
});

test("ttl is an integer number of seconds within bounds", () => {
  assert.equal(isValidTtlSeconds(60), true);
  assert.equal(isValidTtlSeconds(3600), true);
  assert.equal(isValidTtlSeconds(59), false);
  assert.equal(isValidTtlSeconds(3601), false);
  assert.equal(isValidTtlSeconds(900.5), false);
  assert.equal(isValidTtlSeconds("900"), false);
});

test("payload text must be a JSON object or empty", () => {
  assert.deepEqual(parsePayloadText(""), {});
  assert.deepEqual(parsePayloadText('{"script": "x"}'), { script: "x" });
  assert.equal(parsePayloadText("[1]"), null);
  assert.equal(parsePayloadText("42"), null);
  assert.equal(parsePayloadText("{not json"), null);
});

test("only the activator can run, while live", () => {
  assert.equal(canRun(OVERRIDE, "op-admin", NOW), true);
  assert.equal(canRun(OVERRIDE, "op-other", NOW), false);
  assert.equal(canRun(OVERRIDE, null, NOW), false);
  assert.equal(canRun({ ...OVERRIDE, status: "consumed" }, "op-admin", NOW), false);
  assert.equal(canRun(OVERRIDE, "op-admin", new Date("2026-10-21T10:11:00Z")), false);
});

test("activator or admin can revoke a live override", () => {
  assert.equal(canRevoke(OVERRIDE, "op-admin", false, NOW), true);
  assert.equal(canRevoke(OVERRIDE, "op-other", true, NOW), true);
  assert.equal(canRevoke(OVERRIDE, "op-other", false, NOW), false);
  assert.equal(canRevoke({ ...OVERRIDE, status: "revoked" }, "op-admin", true, NOW), false);
});

test("review needs a different admin, once", () => {
  assert.equal(canReview(OVERRIDE, "op-other", true), true);
  assert.equal(canReview(OVERRIDE, "op-admin", true), false);
  assert.equal(canReview(OVERRIDE, "op-other", false), false);
  assert.equal(canReview({ ...OVERRIDE, reviewed_at: "2026-10-21T10:30:00Z" }, "op-other", true), false);
});

test("labels and notification state read plainly", () => {
  assert.equal(statusLabel("consumed"), "Executed");
  assert.equal(notificationLabel(OVERRIDE), "notified 2 recipients");
  assert.equal(
    notificationLabel({ ...OVERRIDE, notified_at: null, notification_error: "no_recipients_configured" }),
    "nobody notified: no alert recipients configured",
  );
  assert.equal(
    notificationLabel({ ...OVERRIDE, notified_at: null, notification_error: "internal_server_error" }),
    "nobody notified: internal_server_error",
  );
  assert.equal(formatTimeRemaining(OVERRIDE.expires_at, NOW), "10 min left");
  assert.equal(formatTimeRemaining(OVERRIDE.expires_at, new Date("2026-10-21T10:10:01Z")), "expired");
});

test("queue orders unreviewed debts first, then live, then newest", () => {
  const reviewed = { ...OVERRIDE, id: "r", status: "consumed" as const, reviewed_at: "2026-10-21T09:00:00Z" };
  const debt = { ...OVERRIDE, id: "d", status: "consumed" as const, created_at: "2026-10-21T08:00:00Z" };
  const live = { ...OVERRIDE, id: "l" };
  assert.deepEqual(
    sortForReview([reviewed, live, debt]).map((row) => row.id),
    ["d", "l", "r"],
  );
});
