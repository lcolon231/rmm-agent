// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";

import {
  conflictChanges,
  draftFromPolicy,
  retentionErrorMessage,
  formatRetention,
  retentionPolicyFromUnknown,
  shortenedCategories,
  validateDraft,
  type RetentionDraft,
  type RetentionPolicy,
} from "../src/lib/retention-policy-core.ts";
import { category, policyPayload } from "./support/retention-policy-fixture.ts";

function policy(overrides: Record<string, unknown> = {}): RetentionPolicy {
  const parsed = retentionPolicyFromUnknown(policyPayload(overrides));
  assert.ok(parsed);
  return parsed;
}

test("a well-formed policy parses with every category in display order", () => {
  const parsed = policy();
  assert.equal(parsed.version, 3);
  assert.equal(parsed.canEdit, true);
  assert.deepEqual(parsed.categories.map((entry) => entry.name), [
    "telemetry_days",
    "command_output_days",
    "command_record_days",
    "inventory_history_per_section",
    "alert_days",
    "notification_days",
    "evidence_default_days",
  ]);
  const inventory = parsed.categories[3];
  assert.equal(inventory.source, "ceiling");
  assert.equal(inventory.override, 5000);
  assert.equal(inventory.unit, "count");
});

test("a policy missing a category, or with an unknown source, is refused", () => {
  const payload = policyPayload();
  delete (payload.categories as Record<string, unknown>).alert_days;
  assert.equal(retentionPolicyFromUnknown(payload), null);
  assert.equal(retentionPolicyFromUnknown(policyPayload({
    categories: { ...policyPayload().categories, telemetry_days: category({ source: "guess" }) },
  })), null);
  assert.equal(retentionPolicyFromUnknown(null), null);
});

test("can_edit is only true when the server says exactly true", () => {
  assert.equal(policy({ can_edit: "yes" }).canEdit, false);
  assert.equal(policy({ can_edit: undefined }).canEdit, false);
});

test("values render with their unit, and 0 reads as keep forever", () => {
  assert.equal(formatRetention(30, "days"), "30 days");
  assert.equal(formatRetention(1, "days"), "1 day");
  assert.equal(formatRetention(50, "count"), "50 snapshots");
  assert.equal(formatRetention(0, "days"), "Keep forever");
});

test("the editor draft starts from the saved overrides, not the effective values", () => {
  const draft = draftFromPolicy(policy());
  assert.deepEqual(draft.telemetry_days, { mode: "inherit", value: "" });
  assert.deepEqual(draft.inventory_history_per_section, { mode: "custom", value: "5000" });
  assert.deepEqual(draft.alert_days, { mode: "forever", value: "" });
  assert.deepEqual(draft.notification_days, { mode: "custom", value: "3" });
});

/** The saved draft with its two clamped overrides brought back inside the bounds. */
function draftWith(changes: Partial<RetentionDraft>): RetentionDraft {
  return {
    ...draftFromPolicy(policy()),
    inventory_history_per_section: { mode: "custom", value: "1000" },
    notification_days: { mode: "inherit", value: "" },
    ...changes,
  };
}

test("re-saving a floor- or ceiling-clamped override is flagged before it reaches the server", () => {
  const result = validateDraft(policy(), draftFromPolicy(policy()));
  assert.ok(!result.ok);
  assert.deepEqual(Object.keys(result.errors).sort(), [
    "inventory_history_per_section",
    "notification_days",
  ]);
});

test("a valid draft resolves to the saved overrides, with null for inherit", () => {
  const result = validateDraft(policy(), draftWith({}));
  assert.ok(result.ok);
  assert.equal(result.values.notification_days, null);
  assert.equal(result.values.telemetry_days, null);
  assert.equal(result.values.alert_days, 0);
  assert.equal(result.values.command_record_days, 400);
});

test("values outside the platform bounds are flagged on their own field", () => {
  const result = validateDraft(policy(), draftWith({
    command_record_days: { mode: "custom", value: "29" },
    telemetry_days: { mode: "custom", value: "3651" },
  }));
  assert.equal(result.ok, false);
  assert.ok(!result.ok);
  assert.match(result.errors.command_record_days ?? "", /at least 30 days/);
  assert.match(result.errors.telemetry_days ?? "", /at most 3650 days/);
  assert.equal(result.errors.alert_days, undefined);
});

test("keep forever is refused where a ceiling applies, and for evidence", () => {
  const result = validateDraft(policy(), draftWith({
    telemetry_days: { mode: "forever", value: "" },
    evidence_default_days: { mode: "forever", value: "" },
  }));
  assert.ok(!result.ok);
  assert.match(result.errors.telemetry_days ?? "", /cannot be kept forever/);
  assert.match(result.errors.evidence_default_days ?? "", /cannot be kept forever/);
});

test("a custom value must be a whole number above zero", () => {
  for (const value of ["", "0", "-5", "7.5", "12abc"]) {
    const result = validateDraft(policy(), draftWith({ telemetry_days: { mode: "custom", value } }));
    assert.ok(!result.ok, value);
    assert.match(result.errors.telemetry_days ?? "", /whole number/, value);
  }
});

test("without a ceiling, any value at or above the minimum is accepted", () => {
  const result = validateDraft(policy(), draftWith({
    evidence_default_days: { mode: "custom", value: "99999" },
  }));
  assert.ok(result.ok);
  assert.equal(result.values.evidence_default_days, 99999);
});

function valuesOf(draft: RetentionDraft) {
  const result = validateDraft(policy(), draft);
  assert.ok(result.ok);
  return result.values;
}

test("lowering a finite value, or ending keep-forever, counts as shortening", () => {
  const values = valuesOf(draftWith({
    telemetry_days: { mode: "custom", value: "20" },
    alert_days: { mode: "custom", value: "365" },
  }));
  // inventory 1000 (ceiling-clamped) saved as 1000 is unchanged, not shorter.
  assert.deepEqual(shortenedCategories(policy(), values), ["telemetry_days", "alert_days"]);
});

test("lengthening, keeping, or inheriting a forever default is never shortening", () => {
  const values = valuesOf(draftWith({
    command_output_days: { mode: "custom", value: "120" },
    command_record_days: { mode: "inherit", value: "" }, // 400 -> platform default 0 (forever)
    evidence_default_days: { mode: "custom", value: "3000" },
  }));
  assert.deepEqual(shortenedCategories(policy(), values), []);
});

test("resetting to platform defaults is compared against the defaults, not the overrides", () => {
  const values = valuesOf(draftWith({
    command_record_days: { mode: "inherit", value: "" },
    inventory_history_per_section: { mode: "inherit", value: "" },
    alert_days: { mode: "inherit", value: "" },
  }));
  // inventory: effective 1000 -> platform default 50.
  assert.deepEqual(shortenedCategories(policy(), values), ["inventory_history_per_section"]);
});

test("422 codes map to a message for the offending field", () => {
  assert.match(retentionErrorMessage("retention_below_minimum") ?? "", /below the platform minimum/);
  assert.match(retentionErrorMessage("retention_above_maximum") ?? "", /above the platform maximum/);
  assert.match(retentionErrorMessage("retention_value_invalid") ?? "", /not allowed/);
  assert.match(retentionErrorMessage("retention_policy_conflict") ?? "", /another administrator/i);
  assert.match(retentionErrorMessage("client_not_found") ?? "", /no longer available/);
  assert.equal(retentionErrorMessage("something_else"), null);
  assert.equal(retentionErrorMessage(undefined), null);
});

test("a conflict lists exactly the overrides the other administrator changed", () => {
  const mine = policy();
  const theirs = policy({
    version: 4,
    set_by: "other@example.test",
    categories: {
      ...policyPayload().categories,
      telemetry_days: category({ effective: 14, source: "tenant", override: 14 }),
      alert_days: category({
        effective: 0, source: "default", override: null, platform_default: 0, minimum: 30,
        maximum: 0, forever_allowed: true,
      }),
    },
  });
  assert.deepEqual(conflictChanges(mine, theirs), [
    { name: "telemetry_days", before: null, after: 14, unit: "days" },
    { name: "alert_days", before: 0, after: null, unit: "days" },
  ]);
  assert.deepEqual(conflictChanges(mine, mine), []);
});
