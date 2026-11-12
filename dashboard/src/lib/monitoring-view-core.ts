// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Presentation rules for the Alerts and Monitoring screens: status words,
 * risk order and URL filters. Every word maps to a field the server returns;
 * an unknown result is never shown as healthy.
 */

import type {
  AlertEmailDeliveryStatus,
  AlertEventType,
  AlertResultStatus,
  AlertState,
  AlertWebhookDeliveryStatus,
  MonitoringAlert,
  MonitoringCheck,
  MonitoringPolicy,
  MonitoringScope,
} from "./monitoring-core.ts";

export type ViewTone = "ok" | "warn" | "crit" | "off" | "info";
export type ToneWord = { tone: ViewTone; label: string };

const RANK: Record<ViewTone, number> = { crit: 0, off: 1, warn: 2, info: 3, ok: 4 };

export function alertStateWord(state: AlertState): ToneWord {
  if (state === "open") return { tone: "warn", label: "Open" };
  if (state === "acknowledged") return { tone: "info", label: "Acknowledged" };
  return { tone: "ok", label: "Resolved" };
}

/** Severity of the latest result. "unknown" stays unknown, never healthy. */
export function alertSeverityWord(status: AlertResultStatus): ToneWord {
  if (status === "critical") return { tone: "crit", label: "Critical" };
  if (status === "warning") return { tone: "warn", label: "Warning" };
  if (status === "ok") return { tone: "ok", label: "Healthy" };
  return { tone: "off", label: "Unknown" };
}

/** How urgent an alert is in a list: resolved ones sink to the bottom. */
export function alertRiskTone(alert: Pick<MonitoringAlert, "state" | "last_result_status">): ViewTone {
  if (alert.state === "resolved") return "ok";
  const severity = alertSeverityWord(alert.last_result_status).tone;
  // An open alert whose latest result is healthy or unknown still needs a look.
  return severity === "ok" ? "warn" : severity;
}

/** Stable: most urgent first, then most recently observed (the server order). */
export function sortAlertsByRisk<T extends Pick<MonitoringAlert, "state" | "last_result_status">>(alerts: readonly T[]): T[] {
  return alerts
    .map((alert, index) => ({ alert, index }))
    .sort((a, b) => RANK[alertRiskTone(a.alert)] - RANK[alertRiskTone(b.alert)] || a.index - b.index)
    .map(({ alert }) => alert);
}

export function alertTitle(checkKey: string): string {
  const words = checkKey.replaceAll("_", " ").trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : "Monitoring check";
}

export const ALERT_FILTERS = ["active", "critical", "warning", "open", "acknowledged", "resolved"] as const;
export type AlertFilter = (typeof ALERT_FILTERS)[number];

export const ALERT_FILTER_LABELS: Record<AlertFilter, string> = {
  active: "Not resolved",
  critical: "Critical",
  warning: "Warning",
  open: "Open",
  acknowledged: "Acknowledged",
  resolved: "Resolved",
};

/** Unknown or missing values fall back to the default: alerts not yet resolved. */
export function parseAlertFilter(value: string | string[] | undefined): AlertFilter {
  const raw = Array.isArray(value) ? value[0] : value;
  return (ALERT_FILTERS as readonly string[]).includes(raw ?? "") ? (raw as AlertFilter) : "active";
}

export function alertMatchesFilter(alert: Pick<MonitoringAlert, "state" | "last_result_status">, filter: AlertFilter): boolean {
  switch (filter) {
    case "active":
      return alert.state !== "resolved";
    case "critical":
    case "warning":
      return alert.state !== "resolved" && alert.last_result_status === filter;
    default:
      return alert.state === filter;
  }
}

export function alertsHref(filter: AlertFilter): string {
  return filter === "active" ? "/alerts" : `/alerts?filter=${filter}`;
}

export type AlertTab = "summary" | "timeline" | "notifications";

export function parseAlertTab(value: string | string[] | undefined): AlertTab {
  const raw = Array.isArray(value) ? value[0] : value;
  return raw === "timeline" || raw === "notifications" ? raw : "summary";
}

const EVENT_WORDS: Record<AlertEventType, string> = {
  state_imported: "Imported from an earlier record",
  opened: "Opened",
  reopened: "Opened again",
  acknowledged: "Acknowledged",
  assigned: "Assignment changed",
  commented: "Note added",
  manual_resolution: "Resolved by a person",
  automatic_recovery: "Resolved on its own",
  policy_revised: "Closed because the policy changed",
  policy_deleted: "Closed because the policy was deleted",
  policy_superseded: "Closed because another policy now applies",
};

export function alertEventWord(type: AlertEventType): string {
  return EVENT_WORDS[type];
}

export function alertEventTone(type: AlertEventType): ViewTone {
  if (type === "opened" || type === "reopened") return "warn";
  if (type === "acknowledged") return "info";
  if (type === "manual_resolution" || type === "automatic_recovery") return "ok";
  return "off";
}

/** Email "sent" means the mail provider accepted it, not that it was read. */
export function emailDeliveryWord(status: AlertEmailDeliveryStatus): ToneWord {
  return {
    pending: { tone: "info", label: "Waiting" },
    sending: { tone: "info", label: "Sending" },
    retrying: { tone: "info", label: "Retrying" },
    sent: { tone: "ok", label: "Sent" },
    failed: { tone: "crit", label: "Failed" },
    suppressed: { tone: "off", label: "Not sent" },
  }[status] as ToneWord;
}

export function webhookDeliveryWord(status: AlertWebhookDeliveryStatus): ToneWord {
  return {
    pending: { tone: "info", label: "Waiting" },
    sending: { tone: "info", label: "Sending" },
    retrying: { tone: "info", label: "Retrying" },
    delivered: { tone: "ok", label: "Delivered" },
    failed: { tone: "crit", label: "Failed" },
    suppressed: { tone: "off", label: "Not sent" },
  }[status] as ToneWord;
}

export function policyStateWord(enabled: boolean): ToneWord {
  return enabled ? { tone: "ok", label: "Active" } : { tone: "off", label: "Disabled" };
}

export function scopeLabel(scope: MonitoringScope, scopeId: string | null): string {
  if (scope === "global" || !scopeId) return "Every managed device";
  return { client: "One client", site: "One site", agent: "One device", global: "Every managed device" }[scope];
}

export type PolicyAlertCounts = { open: number; critical: number };

/** Unresolved alerts per policy, from the alerts the page loaded. */
export function countAlertsByPolicy(alerts: readonly Pick<MonitoringAlert, "policy_id" | "state" | "last_result_status">[]): Map<string, PolicyAlertCounts> {
  const counts = new Map<string, PolicyAlertCounts>();
  for (const alert of alerts) {
    if (alert.state === "resolved") continue;
    const entry = counts.get(alert.policy_id) ?? { open: 0, critical: 0 };
    entry.open += 1;
    if (alert.last_result_status === "critical") entry.critical += 1;
    counts.set(alert.policy_id, entry);
  }
  return counts;
}

/**
 * Risk for a policy row. Without alert data no policy is called healthy:
 * it is shown as "info" (unknown) rather than ok.
 */
export function policyRiskTone(policy: Pick<MonitoringPolicy, "enabled">, counts: PolicyAlertCounts | undefined, alertsKnown: boolean): ViewTone {
  if (!alertsKnown) return policy.enabled ? "info" : "off";
  if (counts?.critical) return "crit";
  if (!policy.enabled) return "off";
  if (counts?.open) return "warn";
  return "ok";
}

export function sortPoliciesByRisk<T extends Pick<MonitoringPolicy, "id" | "enabled">>(
  policies: readonly T[],
  counts: Map<string, PolicyAlertCounts>,
  alertsKnown: boolean,
): T[] {
  return policies
    .map((policy, index) => ({ policy, index }))
    .sort(
      (a, b) =>
        RANK[policyRiskTone(a.policy, counts.get(a.policy.id), alertsKnown)] - RANK[policyRiskTone(b.policy, counts.get(b.policy.id), alertsKnown)] ||
        a.index - b.index,
    )
    .map(({ policy }) => policy);
}

export const POLICY_FILTERS = ["all", "active", "disabled"] as const;
export type PolicyFilter = (typeof POLICY_FILTERS)[number];

export function parsePolicyFilter(value: string | string[] | undefined): PolicyFilter {
  const raw = Array.isArray(value) ? value[0] : value;
  return raw === "active" || raw === "disabled" ? raw : "all";
}

export function policiesHref(filter: PolicyFilter): string {
  return filter === "all" ? "/monitoring" : `/monitoring?state=${filter}`;
}

export type PolicyTab = "rule" | "history";

export function parsePolicyTab(value: string | string[] | undefined): PolicyTab {
  const raw = Array.isArray(value) ? value[0] : value;
  return raw === "history" ? "history" : "rule";
}

const CHECK_WORDS: Record<MonitoringCheck["type"], string> = {
  offline: "Device stops checking in",
  cpu: "Processor use",
  memory: "Memory use",
  disk: "Disk space used",
  service: "Windows service running",
  reboot_pending: "Restart waiting",
  uptime: "Time since last restart",
  patch_age: "Age of missing updates",
};

export function checkTypeWord(type: MonitoringCheck["type"]): string {
  return CHECK_WORDS[type];
}

const OPERATOR_WORDS = { gt: "above", gte: "at or above", lt: "below", lte: "at or below" } as const;

export function thresholdWords(threshold: MonitoringCheck["threshold"]): string {
  if (!threshold) return "Raised when the state changes";
  const op = OPERATOR_WORDS[threshold.op];
  const parts = [
    threshold.warning === null ? null : `Warning ${op} ${threshold.warning}`,
    threshold.critical === null ? null : `Critical ${op} ${threshold.critical}`,
  ].filter(Boolean);
  return parts.length ? parts.join(" · ") : "No limit set";
}

export function intervalWords(seconds: number): string {
  const unit = (value: number, word: string) => `Every ${value === 1 ? word : `${value} ${word}s`}`;
  if (seconds % 3600 === 0) return unit(seconds / 3600, "hour");
  if (seconds % 60 === 0) return unit(seconds / 60, "minute");
  return unit(seconds, "second");
}

export function paramsWords(params: Record<string, unknown>): string {
  const entries = Object.entries(params).sort(([left], [right]) => left.localeCompare(right));
  if (entries.length === 0) return "None";
  return entries.map(([key, value]) => `${key.replaceAll("_", " ")}: ${String(value)}`).join(" · ");
}
