// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  describeThreshold,
  alertEmailDeliveryListFromUnknown,
  alertWebhookDeliveryListFromUnknown,
  formatCheckInterval,
  formatCheckType,
  formatMonitoringScope,
  formatMonitoringTimestamp,
  monitoringPolicyDetailFromUnknown,
  monitoringPolicyListFromUnknown,
  monitoringAlertDetailFromUnknown,
  monitoringAlertListFromUnknown,
  rebootCorrelationPresentation,
  validateAlertActionInput,
  webhookEndpointListFromUnknown,
  webhookEndpointSecretFromUnknown,
  webhookStatusFromUnknown,
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

test("patch-age checks are accepted without weakening the type allowlist", () => {
  const detail = monitoringPolicyDetailFromUnknown({
    ...summary,
    checks: [{
      ...check,
      key: "patch-age",
      type: "patch_age",
      schedule: { interval_seconds: 3600 },
      threshold: { op: "gt", warning: 30, critical: 60 },
    }],
    revisions: [],
  });
  assert.ok(detail);
  assert.equal(detail.checks[0].type, "patch_age");
  assert.equal(formatCheckType(detail.checks[0].type), "patch age");

  assert.equal(
    monitoringPolicyDetailFromUnknown({
      ...summary,
      checks: [{ ...check, type: "future_check" }],
      revisions: [],
    }),
    null,
  );
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
    last_result_detail: { reason: "reboot_pending" },
    reboot_cause: {
      reboot_flagged_updates: [{
        title: "Pending update", kb_id: "KB-PENDING", update_id: null,
        classification: "Security Updates", product: "Windows 11", severity: "Critical",
        reboot_required: true, is_downloaded: true, support_url: null,
        last_deployment_change: null, priority_grade: "P1 - Critical",
      }],
      recent_installs: [{
        kb_id: "KB-RECENT", update_id: "update-1", revision_number: 2,
        title: "Recently installed update", description: null,
        installed_on: "2026-07-31T10:00:00Z", installed_by: "SYSTEM",
        client_application_id: null, support_url: null, result_code: 2, hresult: null,
      }],
      system_reboot_required: true,
      scanned_at: "2026-08-01T09:58:00Z",
      snapshot_received_at: "2026-08-01T09:59:00Z",
    },
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
  assert.equal(detail.last_result_detail?.reason, "reboot_pending");
  assert.equal(detail.reboot_cause?.recent_installs[0].kb_id, "KB-RECENT");
  assert.doesNotMatch(JSON.stringify(detail), /password|secret/);
});

test("alert detail degrades malformed or absent reboot correlation to null", () => {
  const base = { ...alert, events: [], observations: [], last_result_detail: null };
  const absent = monitoringAlertDetailFromUnknown(base);
  assert.ok(absent);
  assert.equal(absent.reboot_cause, null);

  const malformed = monitoringAlertDetailFromUnknown({
    ...base,
    reboot_cause: {
      reboot_flagged_updates: [], recent_installs: "not-a-list",
      system_reboot_required: false, scanned_at: null,
      snapshot_received_at: "2026-08-01T09:59:00Z",
    },
  });
  assert.ok(malformed);
  assert.equal(malformed.reboot_cause, null);
});

test("reboot correlation presentation distinguishes unavailable, evidence, and no-evidence states", () => {
  const unavailable = rebootCorrelationPresentation(
    { reason: "reboot_pending" },
    {
      reboot_flagged_updates: [], recent_installs: [], system_reboot_required: true,
      scanned_at: null, snapshot_received_at: "2026-08-01T09:59:00Z",
    },
  );
  assert.equal(unavailable?.state, "unavailable");
  assert.match(unavailable?.summary ?? "", /agent predates cause reporting/i);

  const sourceDetail = {
    reason: "reboot_pending",
    sources: {
      component_based_servicing: false,
      windows_update: true,
      pending_file_rename: false,
    },
  };
  const correlated = rebootCorrelationPresentation(sourceDetail, {
    reboot_flagged_updates: [],
    recent_installs: [{
      kb_id: "KB-RECENT", update_id: null, revision_number: null, title: "Update",
      description: null, installed_on: "2026-08-01T08:00:00Z", installed_by: null,
      client_application_id: null, support_url: null, result_code: null, hresult: null,
    }],
    system_reboot_required: true,
    scanned_at: "2026-08-01T09:58:00Z",
    snapshot_received_at: "2026-08-01T09:59:00Z",
  });
  assert.equal(correlated?.state, "update_correlated");
  assert.match(correlated?.summary ?? "", /correlation, not proof/i);

  const noEvidence = rebootCorrelationPresentation(sourceDetail, {
    reboot_flagged_updates: [], recent_installs: [], system_reboot_required: false,
    scanned_at: null, snapshot_received_at: "2026-08-01T09:59:00Z",
  });
  assert.equal(noEvidence?.state, "no_evidence");
  assert.match(noEvidence?.summary ?? "", /does not rule out/i);
  assert.equal(rebootCorrelationPresentation(null, null), null);
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

test("webhook endpoint and status parsers never retain secrets or full destinations", () => {
  const endpoint = {
    id: "endpoint-1", name: "Incident relay", url: "https://*.example.test/…",
    event_types: ["opened", "automatic_recovery"], enabled: true,
    current_secret_version: 1, current_secret_key_id: "key-1", version: 1,
    deleted_at: null, created_at: "2026-08-05T10:00:00Z",
    updated_at: "2026-08-05T10:00:00Z", encrypted_secret: "must-not-leak",
  };
  const endpoints = webhookEndpointListFromUnknown([endpoint]);
  assert.ok(endpoints);
  assert.equal(endpoints[0].url, "https://*.example.test/…");
  assert.doesNotMatch(JSON.stringify(endpoints), /encrypted_secret|must-not-leak/);
  const secret = webhookEndpointSecretFromUnknown({
    ...endpoint, secret: "whsec_once", signing_algorithm: "HMAC-SHA256",
    signature_header: "X-NodeLink-Signature",
  });
  assert.ok(secret);
  assert.equal(secret.secret, "whsec_once");
  assert.ok(webhookStatusFromUnknown({
    encryption_key_configured: true, endpoint_count: 1,
    enabled_endpoint_count: 1, endpoint_limit: 50,
    counts: { pending: 0, delivered: 2, failed: 0 }, api_key: "must-not-leak",
  }));
});

test("webhook delivery parser allowlists attempt metadata and rejects payloads", () => {
  const delivery = {
    id: "delivery-1", endpoint_id: "endpoint-1", endpoint_name: "Incident relay",
    alert_id: "alert-1", alert_event_id: "event-1", generation: 1,
    event_type: "opened", destination: "https://*.example.test/…", status: "failed",
    attempt_count: 1, max_attempts: 3, next_attempt_at: "2026-08-05T10:02:00Z",
    last_http_status: 503, last_error_code: "http_503", delivered_at: null,
    created_at: "2026-08-05T10:00:00Z", updated_at: "2026-08-05T10:01:00Z",
    payload: "must-not-leak", destination_url: "https://secret.example/path?token=x",
    attempts: [{
      id: "attempt-1", attempt_number: 1, status: "failed", http_status: 503,
      error_code: "http_503", created_at: "2026-08-05T10:00:00Z",
      completed_at: "2026-08-05T10:01:00Z", response_body: "must-not-leak",
    }],
  };
  const parsed = alertWebhookDeliveryListFromUnknown({ items: [delivery] });
  assert.ok(parsed);
  assert.equal(parsed[0].attempts[0].http_status, 503);
  assert.doesNotMatch(JSON.stringify(parsed), /payload|destination_url|response_body|must-not-leak/);
  assert.equal(alertWebhookDeliveryListFromUnknown({
    items: [{ ...delivery, last_http_status: 700 }],
  }), null);
});
