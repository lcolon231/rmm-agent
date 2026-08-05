// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  describeThreshold,
  alertEmailDeliveryListFromUnknown,
  formatCheckInterval,
  formatMonitoringScope,
  formatMonitoringTimestamp,
  monitoringPolicyDetailFromUnknown,
  monitoringPolicyListFromUnknown,
  monitoringAlertDetailFromUnknown,
  monitoringAlertListFromUnknown,
  validateAlertActionInput,
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

const alert = {
  id: "alert-1", agent_id: "agent-1", policy_id: "policy-1",
  policy_revision_id: "revision-1", check_key: "cpu", state: "open",
  last_result_status: "warning", occurrence_count: 2, total_occurrence_count: 3,
  generation: 1, first_opened_at: "2026-08-01T10:00:00Z",
  opened_at: "2026-08-01T10:00:00Z", last_observed_at: "2026-08-01T10:01:00Z",
  resolved_at: null, last_evaluated_at: "2026-08-01T10:01:00Z",
  last_result_id: "result-1", last_value: 86, resolution_reason: null,
  suppression_window_id: null, suppressed_until: null,
  assigned_to_operator_id: null, assigned_to_email: null,
  acknowledged_at: null, acknowledged_by: null, version: 2,
  created_at: "2026-08-01T10:00:00Z", updated_at: "2026-08-01T10:01:00Z",
};

test("alert list and detail parsers return only allowlisted operational data", () => {
  const list = monitoringAlertListFromUnknown({ items: [{ ...alert, access_token: "secret" }] });
  assert.ok(list);
  assert.doesNotMatch(JSON.stringify(list), /access_token|secret/);
  const detail = monitoringAlertDetailFromUnknown({
    ...alert,
    events: [{
      id: "event-1", alert_id: "alert-1", generation: 1, event_type: "opened",
      from_state: "resolved", to_state: "open", actor: "system", actor_user_id: null,
      comment: null, comment_redacted: false, assigned_to_operator_id: null,
      assigned_to_email: null, source_result_id: "result-1", request_id: null,
      created_at: "2026-08-01T10:00:00Z", password: "secret",
    }],
    observations: [{
      check_result_id: "result-1", alert_id: "alert-1", status: "warning", value: 86,
      evaluated_at: "2026-08-01T10:00:00Z", out_of_order: false,
      created_at: "2026-08-01T10:00:00Z",
    }],
  });
  assert.ok(detail);
  assert.equal(detail.events[0].event_type, "opened");
  assert.doesNotMatch(JSON.stringify(detail), /password|secret/);
});

test("alert action input requires an idempotency key and bounded version", () => {
  assert.deepEqual(validateAlertActionInput({
    request_id: "request-12345678", expected_version: 2, comment: "  checking  ",
  }), { request_id: "request-12345678", expected_version: 2, comment: "checking" });
  assert.equal(validateAlertActionInput({ request_id: "short", expected_version: 2 }), null);
  assert.equal(validateAlertActionInput({ request_id: "request-12345678", expected_version: 0 }), null);
  assert.equal(validateAlertActionInput({
    request_id: "request-12345678", expected_version: 2, comment: "x".repeat(2001),
  }), null);
});

test("email delivery parser allowlists masked history and rejects malformed attempts", () => {
  const delivery = {
    id: "delivery-1", alert_id: "alert-1", alert_event_id: "event-1",
    generation: 1, event_type: "opened", recipient: "f***@example.test",
    status: "failed", attempt_count: 1, max_attempts: 3,
    next_attempt_at: "2026-08-01T10:02:00Z", provider_message_id: null,
    last_error_code: "rate_limited", sent_at: null,
    created_at: "2026-08-01T10:00:00Z", updated_at: "2026-08-01T10:01:00Z",
    attempts: [{
      id: "attempt-1", attempt_number: 1, status: "failed",
      provider_message_id: null, error_code: "rate_limited",
      created_at: "2026-08-01T10:00:00Z", completed_at: "2026-08-01T10:01:00Z",
      authorization: "must-not-leak",
    }],
    text_body: "must-not-leak",
  };
  const parsed = alertEmailDeliveryListFromUnknown({ items: [delivery] });
  assert.ok(parsed);
  assert.equal(parsed[0].recipient, "f***@example.test");
  assert.doesNotMatch(JSON.stringify(parsed), /authorization|text_body|must-not-leak/);
  assert.equal(alertEmailDeliveryListFromUnknown({
    items: [{ ...delivery, attempts: [{ ...delivery.attempts[0], attempt_number: 0 }] }],
  }), null);
});
