// SPDX-License-Identifier: AGPL-3.0-only

export type ComplianceState =
  | "compliant"
  | "non_compliant"
  | "stale"
  | "unknown"
  | "exempt";

export type ComplianceSummary = {
  total_endpoints: number;
  compliant: number;
  non_compliant: number;
  stale: number;
  unknown: number;
  exempt: number;
  total_approved_missing: number;
  truncated: boolean;
};

export type ComplianceEndpoint = {
  agent_id: string;
  hostname: string;
  site_id: string;
  site_name: string;
  client_id: string;
  client_name: string;
  state: ComplianceState;
  policy_id: string | null;
  scanned_at: string | null;
  total_missing: number;
  approved_missing: number;
  deferred_missing: number;
  denied_missing: number;
};

export type ComplianceListData = {
  items: ComplianceEndpoint[];
  page: number;
  page_size: number;
  total: number;
  truncated: boolean;
};

const complianceStates = new Set<ComplianceState>([
  "compliant",
  "non_compliant",
  "stale",
  "unknown",
  "exempt",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonNegativeInteger(value: unknown): value is number {
  return Number.isInteger(value) && (value as number) >= 0;
}

function nullableTimestamp(value: unknown): string | null | undefined {
  if (value === null) return null;
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) return undefined;
  return value;
}

export function summaryFromUnknown(value: unknown): ComplianceSummary | null {
  if (!isRecord(value)) return null;
  const integerFields = [
    "total_endpoints",
    "compliant",
    "non_compliant",
    "stale",
    "unknown",
    "exempt",
    "total_approved_missing",
  ] as const;
  if (
    !integerFields.every((field) => isNonNegativeInteger(value[field]))
    || typeof value.truncated !== "boolean"
  ) {
    return null;
  }
  return {
    total_endpoints: value.total_endpoints as number,
    compliant: value.compliant as number,
    non_compliant: value.non_compliant as number,
    stale: value.stale as number,
    unknown: value.unknown as number,
    exempt: value.exempt as number,
    total_approved_missing: value.total_approved_missing as number,
    truncated: value.truncated,
  };
}

function endpointFromUnknown(value: unknown): ComplianceEndpoint | null {
  if (!isRecord(value)) return null;
  const scannedAt = nullableTimestamp(value.scanned_at);
  const countFields = [
    "total_missing",
    "approved_missing",
    "deferred_missing",
    "denied_missing",
  ] as const;
  if (
    typeof value.agent_id !== "string"
    || typeof value.hostname !== "string"
    || typeof value.site_id !== "string"
    || typeof value.site_name !== "string"
    || typeof value.client_id !== "string"
    || typeof value.client_name !== "string"
    || !complianceStates.has(value.state as ComplianceState)
    || (value.policy_id !== null && typeof value.policy_id !== "string")
    || scannedAt === undefined
    || !countFields.every((field) => isNonNegativeInteger(value[field]))
  ) {
    return null;
  }
  return {
    agent_id: value.agent_id,
    hostname: value.hostname,
    site_id: value.site_id,
    site_name: value.site_name,
    client_id: value.client_id,
    client_name: value.client_name,
    state: value.state as ComplianceState,
    policy_id: value.policy_id as string | null,
    scanned_at: scannedAt,
    total_missing: value.total_missing as number,
    approved_missing: value.approved_missing as number,
    deferred_missing: value.deferred_missing as number,
    denied_missing: value.denied_missing as number,
  };
}

export function listFromUnknown(value: unknown): ComplianceListData | null {
  if (!isRecord(value) || !Array.isArray(value.items)) return null;
  const items = value.items.map(endpointFromUnknown);
  if (
    !items.every((item): item is ComplianceEndpoint => item !== null)
    || !Number.isInteger(value.page)
    || (value.page as number) < 1
    || !Number.isInteger(value.page_size)
    || (value.page_size as number) < 1
    || (value.page_size as number) > 100
    || !isNonNegativeInteger(value.total)
    || typeof value.truncated !== "boolean"
  ) {
    return null;
  }
  return {
    items,
    page: value.page as number,
    page_size: value.page_size as number,
    total: value.total,
    truncated: value.truncated,
  };
}

export function formatComplianceState(state: ComplianceState): string {
  return {
    compliant: "Compliant",
    non_compliant: "Non-compliant",
    stale: "Stale",
    unknown: "Unknown",
    exempt: "Exempt",
  }[state];
}
