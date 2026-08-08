// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  MAX_DISPLAY_MISSING,
  summarizeWindowsUpdates,
  windowsUpdatesFromUnknown,
} from "../src/lib/windows-updates-core.ts";

test("allowlists payload and drops secret-adjacent and titleless rows", () => {
  const view = windowsUpdatesFromUnknown({
    scanned_at: "2026-08-08T00:00:00Z",
    reboot_required: true,
    error_code: null,
    missing: [
      {
        title: "2026-08 Cumulative Update (KB5034123)",
        kb_id: "KB5034123",
        classification: "Security Updates",
        severity: "Critical",
        reboot_required: true,
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
      missing: [{ title: "x", kb_id: null, classification: null, product: null, severity: null, reboot_required: null, support_url: null }],
      installed: [],
    }).headline,
    /1 missing update · reboot required/,
  );
  assert.match(
    summarizeWindowsUpdates({
      scanned_at: null,
      reboot_required: false,
      error_code: "0x8024402c",
      missing: [],
      installed: [],
    }).headline,
    /error/,
  );
});
