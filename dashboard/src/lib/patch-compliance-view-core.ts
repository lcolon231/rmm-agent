// SPDX-License-Identifier: AGPL-3.0-only
//
// Presentation rules for the patch compliance report: which status word and
// tone each server state gets, how a page of rows is ordered, and the URLs the
// filters and exports use. Pure so the core test tier can pin them.

import type { ComplianceEndpoint, ComplianceState, ComplianceSummary } from "./patch-compliance-core.ts";

export type ComplianceTone = "ok" | "warn" | "crit" | "off" | "info";

export const COMPLIANCE_STATES: readonly ComplianceState[] = [
  "non_compliant",
  "stale",
  "unknown",
  "exempt",
  "compliant",
];

type StateView = { label: string; tone: ComplianceTone; reason: string };

// Only a fresh, trusted scan with nothing approved missing is shown as good.
// An old or missing scan is never presented as compliant.
const STATE_VIEW: Record<ComplianceState, StateView> = {
  non_compliant: { label: "Behind", tone: "warn", reason: "Approved updates are missing" },
  stale: { label: "Needs review", tone: "warn", reason: "Last scan is out of date" },
  unknown: { label: "Unknown", tone: "off", reason: "No trusted scan yet" },
  exempt: { label: "Exempt", tone: "off", reason: "No patch policy applies" },
  compliant: { label: "Compliant", tone: "ok", reason: "Every approved update is installed" },
};

export function complianceStateView(state: ComplianceState): StateView {
  return STATE_VIEW[state];
}

/** Behind first, then unverified, then exempt, then compliant; most missing first within a state. */
export function sortComplianceRows(rows: readonly ComplianceEndpoint[]): ComplianceEndpoint[] {
  return rows
    .map((row, index) => ({ row, index }))
    .sort(
      (a, b) =>
        COMPLIANCE_STATES.indexOf(a.row.state) - COMPLIANCE_STATES.indexOf(b.row.state)
        || b.row.approved_missing - a.row.approved_missing
        || a.index - b.index,
    )
    .map(({ row }) => row);
}

/**
 * Share of endpoints that are compliant, rounded down so 99.6% never reads
 * as 100%. Null when there is nothing to measure.
 */
export function compliantPercent(summary: ComplianceSummary): number | null {
  if (summary.total_endpoints === 0) return null;
  return Math.floor((summary.compliant / summary.total_endpoints) * 100);
}

export function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

export type ComplianceQuery = {
  clientId?: string;
  siteId?: string;
  state?: ComplianceState;
  search?: string;
  page: number;
};

export function parseComplianceState(value: string | undefined): ComplianceState | undefined {
  return COMPLIANCE_STATES.find((state) => state === value);
}

export function complianceReportHref(query: ComplianceQuery, change: Partial<ComplianceQuery> = {}): string {
  const next = { ...query, ...change };
  // Changing a filter always returns to the first page.
  const page = change.page ?? ("state" in change || "search" in change ? 1 : query.page);
  const params = new URLSearchParams();
  if (next.clientId) params.set("client_id", next.clientId);
  if (next.siteId) params.set("site_id", next.siteId);
  if (next.state) params.set("state", next.state);
  if (next.search) params.set("search", next.search);
  if (page > 1) params.set("page", String(page));
  return params.size > 0 ? `/patch-compliance?${params}` : "/patch-compliance";
}

export function complianceExportHref(
  format: "csv" | "json",
  scope: { clientId?: string; siteId?: string; state?: ComplianceState },
): string {
  const params = new URLSearchParams({ format });
  if (scope.clientId) params.set("client_id", scope.clientId);
  if (scope.siteId) params.set("site_id", scope.siteId);
  if (scope.state) params.set("state", scope.state);
  return `/api/patch-compliance/export?${params}`;
}
