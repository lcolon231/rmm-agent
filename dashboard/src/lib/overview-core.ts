// SPDX-License-Identifier: AGPL-3.0-only

/** Pure reductions behind the Overview cards; every number comes from a loaded record. */

import type { ApprovalRequest } from "./approvals-core.ts";
import type { AuditEventRecord } from "./audit-core.ts";
import type { MonitoringAlert } from "./monitoring-core.ts";
import type { ComplianceSummary } from "./patch-compliance-core.ts";

export type SeverityRow = { tone: "crit" | "warn" | "off"; label: "Critical" | "Warning" | "Notice"; count: number };

/** Unresolved alerts split by their last result. "unknown" results are notices. */
export function openAlertsBySeverity(alerts: readonly MonitoringAlert[]): { total: number; rows: SeverityRow[] } {
  const open = alerts.filter((alert) => alert.state !== "resolved");
  const count = (status: MonitoringAlert["last_result_status"]) => open.filter((alert) => alert.last_result_status === status).length;
  return {
    total: open.length,
    rows: [
      { tone: "crit", label: "Critical", count: count("critical") },
      { tone: "warn", label: "Warning", count: count("warning") },
      // An alert that has since read "ok" but is not yet resolved is still open; it reads as a notice.
      { tone: "off", label: "Notice", count: count("unknown") + count("ok") },
    ],
  };
}

/**
 * Share of in-scope devices that are fully patched. Exempt devices are left
 * out of both sides; `null` when nothing is in scope, so the page says so
 * rather than showing 0% or 100%.
 */
export function compliancePercent(summary: ComplianceSummary): { percent: number; compliant: number; inScope: number } | null {
  const inScope = summary.total_endpoints - summary.exempt;
  if (inScope <= 0) return null;
  return { percent: Math.floor((summary.compliant / inScope) * 100), compliant: summary.compliant, inScope };
}

/**
 * Pending requests this operator could act on: not their own, soonest to
 * expire first. Requests already decided by them still show on Approvals.
 */
export function waitingForApproval(requests: readonly ApprovalRequest[], operatorId: string, now: Date = new Date()): ApprovalRequest[] {
  return requests
    .filter((request) => request.status === "pending" && request.requested_by_operator_id !== operatorId && Date.parse(request.expires_at) > now.getTime())
    .sort((a, b) => Date.parse(a.expires_at) - Date.parse(b.expires_at));
}

export function formatRequestKind(kind: string): string {
  const words = kind.replaceAll(/[._]/g, " ").trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : "Request";
}

export type ActivityRow = { id: string; ts: string; actor: string; verb: string; target: string | null };

/** Newest first; the target is the device's hostname when the page knows it. */
export function recentActivity(events: readonly AuditEventRecord[], hostnames: ReadonlyMap<string, string>, limit = 6): ActivityRow[] {
  return [...events]
    .sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts))
    .slice(0, limit)
    .map((event) => ({
      id: event.id,
      ts: event.ts,
      actor: event.actor || "System",
      verb: event.action.replaceAll(/[._]/g, " "),
      target: event.agent_id ? (hostnames.get(event.agent_id) ?? `device ${event.agent_id.slice(0, 8)}`) : null,
    }));
}
