// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  effectivePatchPolicyFromUnknown,
  formatPatchAction,
  formatPatchScope,
  patchPolicyDetailFromUnknown,
  patchPolicyListFromUnknown,
} from "../src/lib/patch-policies-core.ts";

const policy = {
  id: "policy-1",
  name: "Baseline",
  scope: "site",
  scope_id: "site-1",
  enabled: true,
  created_at: "2026-08-10T00:00:00Z",
  current_version: 2,
  rule_count: 3,
  default_action: "deny",
  require_maintenance_window: true,
};

test("policy lists are allowlisted and drop secret-adjacent fields", () => {
  const policies = patchPolicyListFromUnknown([{ ...policy, access_token: "session-token-sentinel" }]);
  assert.ok(policies);
  assert.equal(policies[0].name, "Baseline");
  assert.equal(policies[0].default_action, "deny");
  assert.doesNotMatch(JSON.stringify(policies), /session-token-sentinel|access_token/);
});

test("policy parsing fails closed on bad scope, default action, and counts", () => {
  assert.equal(patchPolicyListFromUnknown([{ ...policy, scope: "planet" }]), null);
  assert.equal(patchPolicyListFromUnknown([{ ...policy, default_action: "maybe" }]), null);
  assert.equal(patchPolicyListFromUnknown([{ ...policy, rule_count: -1 }]), null);
  assert.equal(patchPolicyListFromUnknown([{ ...policy, scope: "global", scope_id: "x" }]), null);
  assert.equal(patchPolicyListFromUnknown("nope"), null);
});

test("policy detail validates nested rules and revisions", () => {
  const detail = patchPolicyDetailFromUnknown({
    ...policy,
    rules: [
      { key: "block-defs", action: "deny", match: { classifications: ["Definition Updates"], severities: null, kb_ids: null }, defer_days: null },
      { key: "defer-sec", action: "defer", match: { classifications: ["Security Updates"], severities: null, kb_ids: null }, defer_days: 7 },
    ],
    revisions: [
      { id: "rev-2", version: 2, default_action: "deny", require_maintenance_window: true, change_note: null, created_by: "op@x", created_at: "2026-08-10T00:00:00Z", rules: [] },
    ],
  });
  assert.ok(detail);
  assert.equal(detail.rules.length, 2);
  assert.equal(detail.rules[1].defer_days, 7);
  assert.equal(detail.revisions[0].version, 2);

  // A malformed rule action fails the whole parse.
  assert.equal(
    patchPolicyDetailFromUnknown({ ...policy, rules: [{ key: "x", action: "nuke", match: {}, defer_days: null }], revisions: [] }),
    null,
  );
});

test("effective policy parsing handles the no-policy case and decisions", () => {
  const none = effectivePatchPolicyFromUnknown({
    policy_id: null, policy_name: null, scope: null, default_action: null, require_maintenance_window: false,
    decisions: [{ kb_id: "KB1", update_id: null, title: "Update", classification: "Updates", severity: null, decision: "approve", reason: "no_policy", matched_rule_key: null }],
  });
  assert.ok(none);
  assert.equal(none.policy_id, null);
  assert.equal(none.decisions[0].decision, "approve");

  // An unknown decision value fails closed.
  assert.equal(
    effectivePatchPolicyFromUnknown({ require_maintenance_window: false, decisions: [{ kb_id: null, update_id: null, title: "x", classification: null, severity: null, decision: "explode", reason: "?" }] }),
    null,
  );
});

test("formatters map scope and action to labels", () => {
  assert.equal(formatPatchScope("agent"), "Endpoint");
  assert.equal(formatPatchScope("site"), "Site");
  assert.equal(formatPatchAction("defer"), "Defer");
});
