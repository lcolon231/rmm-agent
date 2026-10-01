// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  buildDispatchRequestBody,
  validateDispatchInput,
} from "../src/lib/command-console-core.ts";
import {
  MAX_DISPLAY_MISSING,
  filterMissingWindowsUpdates,
  installUpdatesResultFromUnknown,
  normalizedUpdateID,
  summarizeWindowsUpdateSelection,
  summarizeWindowsUpdates,
  windowsUpdatePage,
  windowsUpdatePageCount,
  windowsUpdateInstallTargets,
  windowsUpdateScanIsStale,
  windowsUpdateSelectionKey,
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
      results: [],
      reboot: null,
      rebootRequired: true,
      message: "Installed 1 update, 1 failed.",
    },
  );
  assert.equal(installUpdatesResultFromUnknown("not-json"), null);
  assert.equal(installUpdatesResultFromUnknown({ status: "failed", installed_kbs: [], failed_kbs: [] }), null);
});

test("parses per-update outcomes and the reboot decision (issue #53)", () => {
  const result = installUpdatesResultFromUnknown(JSON.stringify({
    status: "success",
    installed_kbs: ["KB5000001"],
    failed_kbs: [],
    reboot_required: true,
    results: [{ identifier: "KB5000001", result_code: 2, hresult: "0x00000000", attempts: 2 }],
    reboot: { policy: "if_required", decision: "scheduled", delay_seconds: 300 },
    message: "ok",
  }));
  assert.ok(result);
  assert.equal(result.results[0].attempts, 2);
  // Older agents omit the per-update reboot flag; it must not read as false.
  assert.equal(result.results[0].rebootRequired, null);
  assert.equal(result.reboot?.decision, "scheduled");
  assert.equal(result.reboot?.delaySeconds, 300);

  // A malformed per-update row or reboot object fails the whole parse.
  assert.equal(installUpdatesResultFromUnknown({ status: "success", installed_kbs: [], failed_kbs: [], reboot_required: false, results: [{ identifier: 5 }] }), null);
  assert.equal(installUpdatesResultFromUnknown({ status: "success", installed_kbs: [], failed_kbs: [], reboot_required: false, reboot: { policy: "x" } }), null);
});

test("parses the per-update reboot_required flag so staged updates are distinguishable", () => {
  const result = installUpdatesResultFromUnknown({
    status: "success",
    installed_kbs: ["KB5126104", "KB5129195"],
    failed_kbs: [],
    reboot_required: true,
    results: [
      { identifier: "KB5126104", result_code: 2, hresult: "0x00000000", attempts: 1, reboot_required: false },
      { identifier: "KB5129195", result_code: 2, hresult: "0x00000000", attempts: 1, reboot_required: true },
    ],
    message: "Installed 2 update(s), 0 failed.",
  });
  assert.ok(result);
  assert.equal(result.results[0].rebootRequired, false);
  assert.equal(result.results[1].rebootRequired, true);
});

test("selects by valid KB ID first, then by valid Windows Update ID (issue #255)", () => {
  const guid = "ABCDEF01-2345-6789-ABCD-EF0123456789";
  assert.equal(windowsUpdateSelectionKey(missingUpdate({ kb_id: "kb5000001" })), "KB5000001");
  assert.equal(
    windowsUpdateSelectionKey(missingUpdate({ kb_id: null, update_id: guid })),
    "abcdef01-2345-6789-abcd-ef0123456789",
  );
  // An unusable KB value falls through to the Update ID rather than disabling the row.
  assert.equal(
    windowsUpdateSelectionKey(missingUpdate({ kb_id: "not-a-kb", update_id: guid })),
    "abcdef01-2345-6789-abcd-ef0123456789",
  );
  assert.equal(normalizedUpdateID(`  ${guid}  `), "abcdef01-2345-6789-abcd-ef0123456789");
});

test("updates with neither a valid KB ID nor a valid Update ID stay unselectable", () => {
  for (const update_id of [null, "", "12345678", "{12345678-1234-1234-1234-1234567890ab}", "zzzzzzzz-1234-1234-1234-1234567890ab"]) {
    assert.equal(windowsUpdateSelectionKey(missingUpdate({ kb_id: null, update_id })), null);
    assert.equal(windowsUpdateSelectionKey(missingUpdate({ kb_id: "KB12", update_id })), null);
  }
  assert.deepEqual(
    windowsUpdateInstallTargets([missingUpdate({ kb_id: null, update_id: "bogus" })]),
    [],
  );
});

test("mixed selections dispatch KB IDs and Update IDs in their own payload fields", () => {
  const driverGuid = "11111111-2222-3333-4444-555555555555";
  const selected = [
    missingUpdate({ kb_id: "KB5000001", update_id: "aaaaaaaa-0000-0000-0000-000000000001" }),
    missingUpdate({ kb_id: null, update_id: driverGuid.toUpperCase(), classification: "Drivers" }),
    // Same KB on a second row (e.g. another product) collapses to one target.
    missingUpdate({ kb_id: "kb5000001", update_id: "aaaaaaaa-0000-0000-0000-000000000002" }),
    missingUpdate({ kb_id: null, update_id: null }),
  ];
  const targets = windowsUpdateInstallTargets(selected);
  assert.deepEqual(targets, ["KB5000001", driverGuid]);

  const input = validateDispatchInput({
    install_all: false,
    kind: "install_updates",
    script: "",
    ttl_seconds: 3_600,
    update_targets: targets,
  });
  assert.ok(input);
  assert.equal(input.install_all, false);
  assert.deepEqual(buildDispatchRequestBody(input).payload, {
    kb_ids: ["KB5000001"],
    update_ids: [driverGuid],
  });
});

test("an Update-ID-only selection dispatches with an empty kb_ids list", () => {
  const guid = "11111111-2222-3333-4444-555555555555";
  const input = validateDispatchInput({
    install_all: false,
    kind: "install_updates",
    script: "",
    ttl_seconds: 3_600,
    update_targets: windowsUpdateInstallTargets([missingUpdate({ kb_id: null, update_id: guid })]),
  });
  assert.ok(input);
  assert.deepEqual(buildDispatchRequestBody(input).payload, { kb_ids: [], update_ids: [guid] });
});

test("an empty selection can neither dispatch nor fall back to install_all", () => {
  const targets = windowsUpdateInstallTargets([missingUpdate({ kb_id: null, update_id: null })]);
  assert.deepEqual(targets, []);
  assert.equal(validateDispatchInput({
    install_all: false,
    kind: "install_updates",
    script: "",
    ttl_seconds: 3_600,
    update_targets: targets,
  }), null);
});

test("search, pagination, and selection summary treat Update-ID-only rows like KB rows", () => {
  const guid = "11111111-2222-3333-4444-555555555555";
  const updates = [
    ...Array.from({ length: 30 }, (_, index) => missingUpdate({
      title: `Update ${index + 1}`,
      kb_id: `KB${5000000 + index}`,
    })),
    missingUpdate({ title: "Firmware", kb_id: null, update_id: guid, reboot_required: true }),
  ];
  const found = filterMissingWindowsUpdates(updates, { query: guid.slice(0, 8), classification: "", excludeDrivers: true });
  assert.deepEqual(found.map((update) => update.title), ["Firmware"]);
  assert.equal(windowsUpdatePage(updates, 2).at(-1)?.title, "Firmware");
  assert.deepEqual(
    summarizeWindowsUpdateSelection(updates.filter((update) => windowsUpdateSelectionKey(update) === guid)),
    { updateCount: 1, driverCount: 0, rebootCount: 1 },
  );
});
