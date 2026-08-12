// SPDX-License-Identifier: AGPL-3.0-only

import type { AuditAnchorRecord, AuditChainVerification, AuditEventRecord } from "@/lib/audit-core";
import type { EndpointListItem } from "@/lib/endpoint-list";
import type { MonitoringAlert } from "@/lib/monitoring-core";

export type FleetSummary = {
  total: number;
  onlineCount: number;
  onlinePercent: number;
  warningCount: number;
  warningPercent: number;
  criticalCount: number;
  criticalPercent: number;
  offlineCount: number;
  offlinePercent: number;
};

export type AttentionItem = {
  id: "offline" | "failed" | "disk" | "stale";
  title: string;
  detail: string;
  count: number;
  endpoint: string;
  site: string;
  observed: string;
  tone: "critical" | "warning";
  action: string;
};

export type SignedAction = {
  id: string;
  time: string;
  title: string;
  target: string;
  actor: string;
  signature: string;
  kind: "action" | "anchor";
};

export type TrustStatus = {
  chainIntact: boolean;
  firstBrokenEventId: string | null;
  anchorCount: number;
  lastAnchorTime: string | null;
  lastAnchorMerkle: string | null;
  activeSigningKeyId: string | null;
  signingKeyStatus: string | null;
  isStale: boolean;
};

export type SigningKeyInfo = {
  active_key_id: string;
  keys: Array<{ key_id: string; status: string; active: boolean }>;
};

/**
 * Calculates fleet summary metrics from real endpoint records.
 * Ensures total count equals sum of status counts and percentages calculate safely.
 */
export function calculateFleetSummary(items: EndpointListItem[], totalCount?: number): FleetSummary {
  const total = totalCount ?? items.length;

  let onlineCount = 0;
  let warningCount = 0;
  let criticalCount = 0;
  let offlineCount = 0;

  for (const item of items) {
    if (item.status === "offline") {
      offlineCount++;
    } else if ((item.status as string) === "critical") {
      criticalCount++;
    } else if (item.status === "pending") {
      warningCount++;
    } else if (item.disk_percent !== null && item.disk_percent >= 90) {
      warningCount++;
    } else {
      onlineCount++;
    }
  }

  const categorized = onlineCount + warningCount + criticalCount + offlineCount;
  if (total > categorized && items.length > 0) {
    const uncounted = total - categorized;
    offlineCount += uncounted;
  }

  const safePercent = (count: number) => {
    if (total <= 0) return 0;
    return Number(((count / total) * 100).toFixed(1));
  };

  return {
    total,
    onlineCount,
    onlinePercent: safePercent(onlineCount),
    warningCount,
    warningPercent: safePercent(warningCount),
    criticalCount,
    criticalPercent: safePercent(criticalCount),
    offlineCount,
    offlinePercent: safePercent(offlineCount),
  };
}

/**
 * Derives attention items from real monitoring alerts and endpoint health metrics.
 */
export function deriveAttentionItems(
  alerts: MonitoringAlert[],
  endpoints: EndpointListItem[],
  now: Date = new Date(),
): AttentionItem[] {
  const items: AttentionItem[] = [];

  // 1. Offline Endpoints (seen > 24h ago or status === 'offline')
  const offlineEndpoints = endpoints.filter((ep) => {
    if (ep.status === "offline") return true;
    if (!ep.last_seen_at) return true;
    const lastSeen = new Date(ep.last_seen_at).getTime();
    return now.getTime() - lastSeen > 24 * 3600 * 1000;
  });

  if (offlineEndpoints.length > 0) {
    const sample = offlineEndpoints[0];
    items.push({
      id: "offline",
      title: "Offline endpoints",
      detail: "Not seen in 24h+",
      count: offlineEndpoints.length,
      endpoint: sample.hostname,
      site: `${sample.client_name} · ${sample.site_name}`,
      observed: sample.last_seen_at
        ? new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }).format(new Date(sample.last_seen_at))
        : "Unseen",
      tone: "critical",
      action: "Investigate",
    });
  }

  // 2. Failed / Critical Alerts
  const openCriticalAlerts = alerts.filter((a) => a.state !== "resolved" && a.last_result_status === "critical");
  if (openCriticalAlerts.length > 0) {
    const sampleAlert = openCriticalAlerts[0];
    const sampleEp = endpoints.find((ep) => ep.id === sampleAlert.agent_id);
    items.push({
      id: "failed",
      title: "Critical monitoring alerts",
      detail: "Critical condition active",
      count: openCriticalAlerts.length,
      endpoint: sampleEp?.hostname ?? sampleAlert.check_key,
      site: sampleEp ? `${sampleEp.client_name} · ${sampleEp.site_name}` : "System",
      observed: sampleAlert.last_observed_at
        ? new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }).format(new Date(sampleAlert.last_observed_at))
        : "Recently",
      tone: "critical",
      action: "Review",
    });
  }

  // 3. High Disk Usage (> 90%)
  const highDiskEndpoints = endpoints.filter((ep) => ep.disk_percent !== null && ep.disk_percent >= 90);
  if (highDiskEndpoints.length > 0) {
    const sample = highDiskEndpoints[0];
    items.push({
      id: "disk",
      title: "High disk usage",
      detail: "> 90% disk used",
      count: highDiskEndpoints.length,
      endpoint: sample.hostname,
      site: `${sample.client_name} · ${sample.site_name}`,
      observed: "Current telemetry",
      tone: "warning",
      action: "Remediate",
    });
  }

  // 4. Stale Check-ins (no check-in in 12h+ but < 24h)
  const staleEndpoints = endpoints.filter((ep) => {
    if (ep.status === "offline") return false;
    if (!ep.last_seen_at) return false;
    const elapsed = now.getTime() - new Date(ep.last_seen_at).getTime();
    return elapsed >= 12 * 3600 * 1000 && elapsed < 24 * 3600 * 1000;
  });

  if (staleEndpoints.length > 0) {
    const sample = staleEndpoints[0];
    items.push({
      id: "stale",
      title: "Stale check-ins",
      detail: "No check-in in 12h+",
      count: staleEndpoints.length,
      endpoint: sample.hostname,
      site: `${sample.client_name} · ${sample.site_name}`,
      observed: sample.last_seen_at
        ? new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }).format(new Date(sample.last_seen_at))
        : "Stale",
      tone: "warning",
      action: "Investigate",
    });
  }

  return items;
}

/**
 * Formats real audit event records into signed action items for the TrustRail component.
 */
export function formatSignedActions(events: AuditEventRecord[]): SignedAction[] {
  return events.map((event) => {
    const tsDate = new Date(event.ts);
    const formattedTime = isNaN(tsDate.getTime())
      ? event.ts
      : new Intl.DateTimeFormat("en-US", { hour: "numeric", minute: "2-digit" }).format(tsDate);

    const actionTitle = formatActionTitle(event.action);
    const targetLabel = event.agent_id
      ? `Agent ${event.agent_id.slice(0, 8)}`
      : event.organization_id
      ? `Org ${event.organization_id.slice(0, 8)}`
      : "System";

    const isAnchor = event.action.includes("anchor");
    const signature = event.seq !== null ? `Seq #${event.seq}` : event.id.slice(0, 8).toUpperCase();

    return {
      id: event.id,
      time: formattedTime,
      title: actionTitle,
      target: targetLabel,
      actor: event.actor || "System",
      signature,
      kind: isAnchor ? "anchor" : "action",
    };
  });
}

function formatActionTitle(action: string): string {
  const words = action.split(/[_.]/);
  return words
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

/**
 * Prepares trust verification status from audit chain and anchor API results.
 */
export function formatTrustStatus(
  chain: AuditChainVerification | null,
  anchors: AuditAnchorRecord[] | null,
  signingKeys: SigningKeyInfo | null,
  isStale = false,
): TrustStatus {
  const latestAnchor = anchors && anchors.length > 0 ? anchors[anchors.length - 1] : null;

  return {
    chainIntact: chain?.intact ?? true,
    firstBrokenEventId: chain?.first_broken_event_id ?? null,
    anchorCount: anchors?.length ?? 0,
    lastAnchorTime: latestAnchor ? latestAnchor.created_at : null,
    lastAnchorMerkle: latestAnchor ? latestAnchor.merkle_root : null,
    activeSigningKeyId: signingKeys?.active_key_id ?? null,
    signingKeyStatus: signingKeys ? (signingKeys.keys.find((k) => k.active)?.status ?? "Active") : null,
    isStale,
  };
}
