// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  collectionLagSeconds,
  describeItem,
  diffIsEmpty,
  formatBytes,
  formatInventoryTimestamp,
  formatLag,
  formatValue,
  hasSuspiciousLag,
  payloadLists,
  payloadRows,
  resolveSection,
  sectionLabel,
  statusExplanation,
  statusLabel,
  statusTone,
  totalChanges,
  type InventorySectionRecord,
} from "../src/lib/inventory-core.ts";

function record(overrides: Partial<InventorySectionRecord> = {}): InventorySectionRecord {
  return {
    id: "snap-1",
    agent_id: "agent-1",
    section: "system",
    status: "ok",
    schema_version: 1,
    content_hash: "a".repeat(64),
    byte_size: 512,
    payload: {},
    collected_at: "2026-07-31T10:00:00Z",
    received_at: "2026-07-31T10:00:05Z",
    ...overrides,
  };
}

// The rule the whole surface depends on: a section nobody could read must
// never render like a section that was read and found empty.
test("a denied read is a failure tone, not a neutral one", () => {
  assert.equal(statusTone("permission_denied"), "failed");
  assert.equal(statusTone("unavailable"), "failed");
  assert.match(statusExplanation("permission_denied"), /nobody looked/);
});

test("partial and unsupported are neither healthy nor failures", () => {
  // A bounded list and a machine that genuinely lacks a feature are both
  // correct outcomes, but neither is a clean bill of health.
  assert.equal(statusTone("partial"), "unknown");
  assert.equal(statusTone("unsupported"), "unknown");
  assert.equal(statusTone("ok"), "verified");
  assert.match(statusExplanation("unsupported"), /not evidence of a problem/);
});

test("every status has a label and an explanation", () => {
  for (const status of ["ok", "partial", "unavailable", "unsupported", "permission_denied"] as const) {
    assert.ok(statusLabel(status).length > 0, status);
    assert.ok(statusExplanation(status).length > 0, status);
  }
});

test("section labels are readable and unknown sections degrade gracefully", () => {
  assert.equal(sectionLabel("installed_software"), "Installed software");
  assert.equal(sectionLabel("security_bitlocker"), "BitLocker");
  // A section added by a newer server must not render as a blank.
  assert.equal(sectionLabel("future_section"), "future section");
});

test("collection lag is surfaced so stale values are not read as current", () => {
  assert.equal(collectionLagSeconds(record()), 5);
  assert.equal(hasSuspiciousLag(5), false);

  const queued = record({
    collected_at: "2026-07-31T00:00:00Z",
    received_at: "2026-07-31T10:00:00Z",
  });
  const lag = collectionLagSeconds(queued);
  assert.equal(lag, 36_000);
  assert.equal(hasSuspiciousLag(lag), true);
  assert.equal(formatLag(lag!), "10h");
});

test("a clock-skewed endpoint reporting a negative lag is still flagged", () => {
  const skewed = record({
    collected_at: "2026-07-31T20:00:00Z",
    received_at: "2026-07-31T10:00:00Z",
  });
  const lag = collectionLagSeconds(skewed);
  assert.equal(lag, -36_000);
  assert.equal(hasSuspiciousLag(lag), true);
});

test("unparseable timestamps yield no lag rather than a bogus number", () => {
  assert.equal(collectionLagSeconds(record({ collected_at: "nope" })), null);
  assert.equal(hasSuspiciousLag(null), false);
  assert.equal(formatInventoryTimestamp("nope"), "Never");
  assert.equal(formatInventoryTimestamp(null), "Never");
});

test("timestamps render in UTC", () => {
  const formatted = formatInventoryTimestamp("2026-07-31T10:00:00Z");
  assert.match(formatted, /UTC/);
  assert.match(formatted, /Jul 31, 2026/);
});

test("payload rows and lists are separated and sorted", () => {
  const payload = {
    model: "X1",
    volumes: [{ mount_point: "C:" }],
    manufacturer: "Contoso",
    disks: [],
  };
  assert.deepEqual(payloadRows(payload).map((row) => row.key), ["manufacturer", "model"]);
  assert.deepEqual(payloadLists(payload).map((list) => list.key), ["disks", "volumes"]);
});

test("values render without inventing data for absent fields", () => {
  assert.equal(formatValue(null), "—");
  assert.equal(formatValue(undefined), "—");
  assert.equal(formatValue(true), "Yes");
  assert.equal(formatValue(false), "No");
  assert.equal(formatValue([]), "(none)");
  assert.equal(formatValue(["a", "b"]), "a, b");
  assert.equal(formatValue({ b: 2, a: 1 }), "a: 1 · b: 2");
});

test("false is rendered as No, never as an absent value", () => {
  // realtime_protection_enabled=false is a finding; showing it as "—" would
  // hide an unprotected endpoint.
  assert.notEqual(formatValue(false), formatValue(null));
});

test("list items are described by their identifying field", () => {
  assert.equal(describeItem({ name: "7-Zip", version: "23.01" }), "7-Zip 23.01");
  assert.equal(describeItem({ mount_point: "C:", protection_status: "on" }), "C:");
  assert.equal(describeItem("Contoso AV"), "Contoso AV");
});

test("empty diffs are detected so a no-change view reads as such", () => {
  assert.equal(diffIsEmpty(null), true);
  assert.equal(diffIsEmpty({ field_changes: [], list_changes: {} }), true);
  assert.equal(
    diffIsEmpty({ field_changes: [{ field: "model", from: "X", to: "Y" }], list_changes: {} }),
    false,
  );
});

test("change totals sum every category", () => {
  assert.equal(
    totalChanges({ fields_changed: 1, items_added: 2, items_removed: 3, items_changed: 4 }),
    10,
  );
  assert.equal(totalChanges({}), 0);
});

test("section names from the URL are validated against the server's list", () => {
  const known = ["system", "installed_software"];
  assert.equal(resolveSection("system", known), "system");
  assert.equal(resolveSection("made_up", known), null);
  assert.equal(resolveSection(undefined, known), null);
});

test("byte sizes are readable at every scale", () => {
  assert.equal(formatBytes(512), "512 B");
  assert.equal(formatBytes(2048), "2.0 KiB");
  assert.equal(formatBytes(5 * 1024 * 1024), "5.0 MiB");
});
