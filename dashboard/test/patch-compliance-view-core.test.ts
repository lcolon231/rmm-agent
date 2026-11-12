// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { complianceReportHref, complianceExportHref, complianceStateView, compliantPercent } from "../src/lib/patch-compliance-view-core.ts";

test("compliance navigation preserves scope and search while resetting filter pagination", () => {
  const query = { clientId: "client", siteId: "site", search: "workstation", page: 3 };
  const url = new URL(complianceReportHref(query, { state: "unknown" }), "https://example.test");
  assert.equal(url.searchParams.get("client_id"), "client");
  assert.equal(url.searchParams.get("site_id"), "site");
  assert.equal(url.searchParams.get("search"), "workstation");
  assert.equal(url.searchParams.get("page"), null);
  assert.equal(url.searchParams.get("state"), "unknown");
  assert.equal(complianceExportHref("csv", query), "/api/patch-compliance/export?format=csv&client_id=client&site_id=site");
});

test("missing and stale scans never receive a healthy tone and percentages never round up", () => {
  assert.equal(complianceStateView("unknown").tone, "off");
  assert.equal(complianceStateView("stale").tone, "warn");
  const summary = { total_endpoints: 1000, compliant: 999, non_compliant: 1, stale: 0, unknown: 0, exempt: 0, total_approved_missing: 1, truncated: false };
  assert.equal(compliantPercent(summary), 99);
  assert.equal(compliantPercent({ ...summary, total_endpoints: 0, compliant: 0 }), null);
});
