// SPDX-License-Identifier: AGPL-3.0-only

/**
 * One status vocabulary for devices, shared by Overview and Endpoints.
 *
 * Critical comes only from an open critical monitoring alert: the dashboard
 * never escalates a device on its own guess. High readings and open warning
 * alerts are warnings; a device that has not finished enrolling is waiting.
 */

import type { EndpointListItem } from "./endpoint-list.ts";
import type { MonitoringAlert } from "./monitoring-core.ts";

export type DeviceTone = "crit" | "off" | "warn" | "info" | "ok";

export type DeviceStatus = {
  tone: DeviceTone;
  label: "Critical" | "Offline" | "Warning" | "Waiting" | "Healthy";
  reason: string;
};

export const READING_LIMIT = 90;

const RANK: Record<DeviceTone, number> = { crit: 0, off: 1, warn: 2, info: 3, ok: 4 };

export type AlertIndex = Map<string, { critical: number; warning: number }>;

/** Open (unresolved) alerts per device, by severity. */
export function indexOpenAlerts(alerts: readonly MonitoringAlert[]): AlertIndex {
  const index: AlertIndex = new Map();
  for (const alert of alerts) {
    if (alert.state === "resolved") continue;
    if (alert.last_result_status !== "critical" && alert.last_result_status !== "warning") continue;
    const entry = index.get(alert.agent_id) ?? { critical: 0, warning: 0 };
    entry[alert.last_result_status] += 1;
    index.set(alert.agent_id, entry);
  }
  return index;
}

function plural(count: number, word: string) {
  return `${count} ${word}${count === 1 ? "" : "s"}`;
}

function highReading(device: EndpointListItem): string | null {
  const readings: Array<[string, number | null]> = [
    ["Disk", device.disk_percent],
    ["Memory", device.mem_percent],
    ["Processor", device.cpu_percent],
  ];
  const high = readings
    .filter((entry): entry is [string, number] => entry[1] !== null && entry[1] >= READING_LIMIT)
    .sort((a, b) => b[1] - a[1])[0];
  return high ? `${high[0]} at ${Math.round(high[1])}%` : null;
}

export function deviceStatus(device: EndpointListItem, alerts: AlertIndex, now: Date = new Date()): DeviceStatus {
  const open = alerts.get(device.id);
  if (open && open.critical > 0) {
    return { tone: "crit", label: "Critical", reason: `${plural(open.critical, "critical alert")} open` };
  }
  if (device.status === "offline") {
    return { tone: "off", label: "Offline", reason: device.last_seen_at ? `No check-in since ${formatSeen(device.last_seen_at, now)}` : "Has never checked in" };
  }
  const reading = highReading(device);
  if (reading) return { tone: "warn", label: "Warning", reason: reading };
  if (open && open.warning > 0) {
    return { tone: "warn", label: "Warning", reason: `${plural(open.warning, "warning")} open` };
  }
  if (device.status === "pending") return { tone: "info", label: "Waiting", reason: "Enrolment not finished" };
  return { tone: "ok", label: "Healthy", reason: "No open problems" };
}

export function riskRank(tone: DeviceTone): number {
  return RANK[tone];
}

/**
 * Devices that need someone, most urgent first, de-duplicated across the
 * lists the page loaded. Healthy and waiting devices are left out.
 */
export function attentionDevices(
  lists: ReadonlyArray<readonly EndpointListItem[]>,
  alerts: AlertIndex,
  now: Date = new Date(),
): Array<{ device: EndpointListItem; status: DeviceStatus }> {
  const seen = new Map<string, EndpointListItem>();
  for (const list of lists) for (const device of list) if (!seen.has(device.id)) seen.set(device.id, device);
  return [...seen.values()]
    .map((device) => ({ device, status: deviceStatus(device, alerts, now) }))
    .filter(({ status }) => status.tone === "crit" || status.tone === "off" || status.tone === "warn")
    .sort((a, b) => riskRank(a.status.tone) - riskRank(b.status.tone) || a.device.hostname.localeCompare(b.device.hostname));
}

/** "just now", "4 min ago", "3 h ago", "yesterday", "3 Nov". */
export function formatSeen(iso: string, now: Date = new Date()): string {
  const at = Date.parse(iso);
  if (Number.isNaN(at)) return "unknown";
  const seconds = Math.max(0, Math.round((now.getTime() - at) / 1000));
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86_400) return `${Math.floor(seconds / 3600)} h ago`;
  if (seconds < 172_800) return "yesterday";
  return new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short" }).format(new Date(at));
}
