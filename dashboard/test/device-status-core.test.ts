// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";

import { attentionDevices, deviceStatus, formatSeen, indexOpenAlerts } from "../src/lib/device-status-core.ts";
import type { EndpointListItem } from "../src/lib/endpoint-list.ts";
import type { MonitoringAlert } from "../src/lib/monitoring-core.ts";

const now = new Date("2026-11-11T12:00:00Z");

function device(overrides: Partial<EndpointListItem> = {}): EndpointListItem {
  return {
    id: "a1",
    hostname: "PHX-FD-02",
    os: "Windows",
    os_version: "11",
    agent_version: "1.4.0",
    status: "online",
    last_seen_at: "2026-11-11T11:58:00Z",
    client_id: "c1",
    client_name: "Lakeshore",
    site_id: "s1",
    site_name: "Main office",
    cpu_percent: 12,
    mem_percent: 40,
    disk_percent: 55,
    logged_in_user: null,
    ...overrides,
  };
}

function alert(agentId: string, status: MonitoringAlert["last_result_status"], state: MonitoringAlert["state"] = "open"): MonitoringAlert {
  return { agent_id: agentId, last_result_status: status, state } as MonitoringAlert;
}

test("critical only comes from an open critical alert, never from a reading", () => {
  const none = indexOpenAlerts([]);
  assert.equal(deviceStatus(device({ disk_percent: 99 }), none, now).tone, "warn");
  assert.deepEqual(deviceStatus(device(), indexOpenAlerts([alert("a1", "critical"), alert("a1", "critical")]), now), {
    tone: "crit",
    label: "Critical",
    reason: "2 critical alerts open",
  });
  assert.equal(deviceStatus(device(), indexOpenAlerts([alert("a1", "critical", "resolved")]), now).tone, "ok", "resolved alerts do not count");
});

test("an offline device explains when it was last seen", () => {
  const none = indexOpenAlerts([]);
  assert.deepEqual(deviceStatus(device({ status: "offline", last_seen_at: "2026-11-10T09:00:00Z" }), none, now), {
    tone: "off",
    label: "Offline",
    reason: "No check-in since yesterday",
  });
  assert.equal(deviceStatus(device({ status: "offline", last_seen_at: null }), none, now).reason, "Has never checked in");
});

test("the highest reading at or above 90% is named", () => {
  const status = deviceStatus(device({ cpu_percent: 91, mem_percent: 96.4, disk_percent: 90 }), indexOpenAlerts([]), now);
  assert.equal(status.reason, "Memory at 96%");
  assert.equal(deviceStatus(device({ disk_percent: 89.9 }), indexOpenAlerts([]), now).tone, "ok");
});

test("pending devices are waiting, not healthy and not a problem", () => {
  assert.equal(deviceStatus(device({ status: "pending" }), indexOpenAlerts([]), now).label, "Waiting");
});

test("attention is de-duplicated across lists, risk-ordered, and leaves healthy devices out", () => {
  const alerts = indexOpenAlerts([alert("crit", "critical"), alert("warn", "warning")]);
  const rows = attentionDevices(
    [
      [device({ id: "off", hostname: "B-OFF", status: "offline" })],
      [device({ id: "ok", hostname: "A-OK" }), device({ id: "warn", hostname: "C-WARN" }), device({ id: "off", hostname: "B-OFF", status: "offline" })],
      [device({ id: "crit", hostname: "D-CRIT" }), device({ id: "wait", hostname: "E-WAIT", status: "pending" })],
    ],
    alerts,
    now,
  );
  assert.deepEqual(rows.map((row) => row.device.hostname), ["D-CRIT", "B-OFF", "C-WARN"]);
});

test("seen times read in plain words", () => {
  assert.equal(formatSeen("2026-11-11T11:59:40Z", now), "just now");
  assert.equal(formatSeen("2026-11-11T11:56:00Z", now), "4 min ago");
  assert.equal(formatSeen("2026-11-11T09:00:00Z", now), "3 h ago");
  assert.equal(formatSeen("2026-11-03T09:00:00Z", now), "3 Nov");
  assert.equal(formatSeen("garbage", now), "unknown");
});
