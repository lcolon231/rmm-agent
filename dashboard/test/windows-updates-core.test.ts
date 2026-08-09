// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  MAX_DISPLAY_MISSING,
  filterMissingWindowsUpdates,
  installUpdatesResultFromUnknown,
  summarizeWindowsUpdateSelection,
  summarizeWindowsUpdates,
  windowsUpdatePage,
  windowsUpdatePageCount,
  windowsUpdateScanIsStale,
  windowsUpdatesFromUnknown,
  type MissingUpdateView,
} from "../src/lib/windows-updates-core.ts";

function missingUpdate(overrides: Partial<MissingUpdateView> = {}): MissingUpdateView {
  return {
    title: "2026-08 Update",
    kb_id: "KB5034123",
    update_id: "12345678-1234-1234-1234-1234567890ab",
    classification: "Security Updates",
    product: "Windows 11",
    severity: "Important",
    reboot_required: false,
    is_downloaded: false,
    support_url: null,
    last_deployment_change: "2026-08-01T00:00:00Z",
    priority_grade: "P2 - High",
    ...overrides,
  };
}

test("allowlists payload and drops secret-adjacent and titleless rows", () => {
  const view = windowsUpdatesFromUnknown({
    scanned_at: "2026-08-08T00:00:00Z",
    reboot_required: true,
    error_code: null,
    history_error_code: null,
    missing: [
      {
        title: "2026-08 Cumulative Update (KB5034123)",
        kb_id: "KB5034123",
        classification: "Security Updates",
        severity: "Critical",
        reboot_required: true,
        is_downloaded: true,
        update_id: "12345678-1234-1234-1234-1234567890ab",
        last_deployment_change: "2026-08-01T00:00:00Z",
        priority_grade: "P1 - Critical",
        support_url: "https://support.microsoft.com/kb/5034123",
        access_token: "session-token-sentinel",
      },
      { kb_id: "KB000" }, // titleless -> dropped
    ],
    installed: [{ kb_id: "KB5030211", installed_on: "2026-07-01T00:00:00Z" }],
  });
  assert.ok(view);
  assert.equal(view.missing.length, 1);
  assert.equal(view.missing[0].severity, "Critical");
  assert.equal(view.missing[0].is_downloaded, true);
  assert.equal(view.missing[0].priority_grade, "P1 - Critical");
  assert.equal(view.installed.length, 1);
  assert.doesNotMatch(JSON.stringify(view), /session-token-sentinel|access_token/);
});

test("returns null for a non-object payload", () => {
  assert.equal(windowsUpdatesFromUnknown(null), null);
  assert.equal(windowsUpdatesFromUnknown("nope"), null);
});

test("missing/installed arrays are capped for display", () => {
  const missing = Array.from({ length: MAX_DISPLAY_MISSING + 10 }, () => ({
    title: "Update",
  }));
  const view = windowsUpdatesFromUnknown({ missing, installed: [] });
  assert.ok(view);
  assert.equal(view.missing.length, MAX_DISPLAY_MISSING);
});

test("summary headline reflects missing count, error, and reboot", () => {
  assert.equal(
    summarizeWindowsUpdates({
      scanned_at: null,
      reboot_required: false,
      error_code: null,
      history_error_code: null,
      missing: [],
      installed: [],
    }).headline,
    "No missing updates",
  );
  assert.match(
    summarizeWindowsUpdates({
      scanned_at: null,
      reboot_required: true,
      error_code: null,
      history_error_code: null,
      missing: [missingUpdate({ title: "x", kb_id: null })],
      installed: [],
    }).headline,
    /1 missing update · reboot required/,
  );
  assert.match(
    summarizeWindowsUpdates({
      scanned_at: null,
      reboot_required: false,
      error_code: "0x8024402c",
      history_error_code: null,
      missing: [],
      installed: [],
    }).headline,
    /error/,
  );
  assert.match(
    summarizeWindowsUpdates({
      scanned_at: null,
      reboot_required: false,
      error_code: null,
      history_error_code: "0x8024000c",
      missing: [],
      installed: [],
    }).headline,
    /history unavailable/,
  );
});

test("filters the complete missing list by search, classification, and driver exclusion", () => {
  const updates = [
    missingUpdate({ title: "Cumulative security update", kb_id: "KB5000001" }),
    missingUpdate({
      title: "Contoso display driver",
      kb_id: null,
      classification: "Drivers",
      product: "Display adapter",
    }),
    missingUpdate({
      title: "Servicing stack",
      kb_id: "KB5000002",
      classification: "Critical Updates",
      severity: "Critical",
    }),
  ];

  assert.deepEqual(
    filterMissingWindowsUpdates(updates, {
      query: "critical",
      classification: "Critical Updates",
      excludeDrivers: true,
    }).map((update) => update.kb_id),
    ["KB5000002"],
  );
  assert.equal(
    filterMissingWindowsUpdates(updates, { query: "", classification: "", excludeDrivers: true }).length,
    2,
  );
  assert.equal(
    filterMissingWindowsUpdates(updates, { query: "display", classification: "", excludeDrivers: false }).length,
    1,
  );
});

test("paginates bounded rendering without dropping rows from the full scan", () => {
  const updates = Array.from({ length: 66 }, (_, index) => missingUpdate({
    title: `Update ${index + 1}`,
    kb_id: `KB${5000000 + index}`,
  }));
  assert.equal(windowsUpdatePageCount(updates.length), 3);
  assert.equal(windowsUpdatePage(updates, 1).length, 25);
  assert.equal(windowsUpdatePage(updates, 3).length, 16);
  assert.equal(windowsUpdatePage(updates, 99)[0].title, "Update 51");
});

test("confirmation totals identify drivers and reboot implications", () => {
  assert.deepEqual(
    summarizeWindowsUpdateSelection([
      missingUpdate({ classification: "Drivers", reboot_required: true }),
      missingUpdate({ kb_id: "KB5000002", reboot_required: false }),
      missingUpdate({ kb_id: "KB5000003", reboot_required: true }),
    ]),
    { updateCount: 3, driverCount: 1, rebootCount: 2 },
  );
});

test("stale scan detection treats missing and invalid timestamps as unsafe", () => {
  const now = Date.parse("2026-08-09T12:00:00Z");
  assert.equal(windowsUpdateScanIsStale("2026-08-09T11:00:00Z", now), false);
  assert.equal(windowsUpdateScanIsStale("2026-08-08T12:00:00Z", now), true);
  assert.equal(windowsUpdateScanIsStale(null, now), true);
  assert.equal(windowsUpdateScanIsStale("not-a-date", now), true);
});

test("parses successful and failed install results for structured rendering", () => {
  assert.deepEqual(
    installUpdatesResultFromUnknown(JSON.stringify({
      status: "partial",
      installed_kbs: ["KB5000001"],
      failed_kbs: ["KB5000002"],
      reboot_required: true,
      message: "Installed 1 update, 1 failed.",
    })),
    {
      status: "partial",
      installedKBs: ["KB5000001"],
      failedKBs: ["KB5000002"],
      rebootRequired: true,
      message: "Installed 1 update, 1 failed.",
    },
  );
  assert.equal(installUpdatesResultFromUnknown("not-json"), null);
  assert.equal(installUpdatesResultFromUnknown({ status: "failed", installed_kbs: [], failed_kbs: [] }), null);
});
