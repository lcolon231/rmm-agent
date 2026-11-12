// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { alertSeverityWord, policyRiskTone, scopeLabel, emailDeliveryWord, sortAlertsByRisk } from "../src/lib/monitoring-view-core.ts";
test("unknown results and missing alert data are never healthy", () => {
  assert.equal(alertSeverityWord("unknown").tone, "off");
  assert.notEqual(policyRiskTone({ enabled: true }, undefined, false), "ok");
  assert.equal(scopeLabel("site", null), "Target not recorded");
  assert.equal(emailDeliveryWord("sent").label, "Sent");
});
test("unresolved critical alerts sort ahead of warnings and resolved alerts", () => {
  const rows = sortAlertsByRisk([{ state: "resolved" as const, last_result_status: "critical" as const }, { state: "open" as const, last_result_status: "warning" as const }, { state: "open" as const, last_result_status: "critical" as const }]);
  assert.equal(rows[0].last_result_status, "critical");
  assert.equal(rows[0].state, "open");
  assert.equal(rows[2].state, "resolved");
});
