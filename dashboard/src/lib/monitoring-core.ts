// SPDX-License-Identifier: AGPL-3.0-only

export type MonitoringScope = "global" | "client" | "site" | "agent";
export type CheckType = "offline" | "cpu" | "memory" | "disk" | "service" | "reboot_pending" | "uptime";
export type ThresholdOp = "gt" | "gte" | "lt" | "lte";

export type MonitoringCheck = {
  key: string;
  type: CheckType;
  enabled: boolean;
  schedule: { interval_seconds: number };
  threshold: {
    op: ThresholdOp;
    warning: number | null;
    critical: number | null;
  } | null;
  hysteresis: { raise_samples: number; clear_samples: number };
  params: Record<string, unknown>;
};

export type MonitoringPolicyRevision = {
  id: string;
  version: number;
  change_note: string | null;
  created_by: string | null;
  created_at: string;
  checks: MonitoringCheck[];
};

export type MonitoringPolicy = {
  id: string;
  name: string;
  scope: MonitoringScope;
  scope_id: string | null;
  enabled: boolean;
  created_at: string;
  current_version: number;
  check_count: number;
};

export type MonitoringPolicyDetail = MonitoringPolicy & {
  checks: MonitoringCheck[];
  revisions: MonitoringPolicyRevision[];
};

const scopes = new Set<MonitoringScope>(["global", "client", "site", "agent"]);
const checkTypes = new Set<CheckType>([
  "offline",
  "cpu",
  "memory",
  "disk",
  "service",
  "reboot_pending",
  "uptime",
]);
const thresholdOps = new Set<ThresholdOp>(["gt", "gte", "lt", "lte"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isTimestamp(value: unknown): value is string {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

function checkFromUnknown(value: unknown): MonitoringCheck | null {
  if (!isRecord(value) || !isRecord(value.schedule) || !isRecord(value.hysteresis)) return null;
  const threshold = value.threshold;
  if (
    typeof value.key !== "string"
    || !checkTypes.has(value.type as CheckType)
    || typeof value.enabled !== "boolean"
    || typeof value.schedule.interval_seconds !== "number"
    || typeof value.hysteresis.raise_samples !== "number"
    || typeof value.hysteresis.clear_samples !== "number"
    || !isRecord(value.params)
  ) {
    return null;
  }
  let normalizedThreshold: MonitoringCheck["threshold"] = null;
  if (threshold !== null) {
    if (
      !isRecord(threshold)
      || !thresholdOps.has(threshold.op as ThresholdOp)
      || (threshold.warning !== null && typeof threshold.warning !== "number")
      || (threshold.critical !== null && typeof threshold.critical !== "number")
    ) {
      return null;
    }
    normalizedThreshold = {
      op: threshold.op as ThresholdOp,
      warning: threshold.warning as number | null,
      critical: threshold.critical as number | null,
    };
  }
  return {
    key: value.key,
    type: value.type as CheckType,
    enabled: value.enabled,
    schedule: { interval_seconds: value.schedule.interval_seconds },
    threshold: normalizedThreshold,
    hysteresis: {
      raise_samples: value.hysteresis.raise_samples,
      clear_samples: value.hysteresis.clear_samples,
    },
    params: { ...value.params },
  };
}

function checksFromUnknown(value: unknown): MonitoringCheck[] | null {
  if (!Array.isArray(value)) return null;
  const checks = value.map(checkFromUnknown);
  return checks.every((check): check is MonitoringCheck => check !== null) ? checks : null;
}

export function monitoringPolicyFromUnknown(value: unknown): MonitoringPolicy | null {
  if (!isRecord(value)) return null;
  if (
    typeof value.id !== "string"
    || typeof value.name !== "string"
    || !scopes.has(value.scope as MonitoringScope)
    || (value.scope_id !== null && typeof value.scope_id !== "string")
    || typeof value.enabled !== "boolean"
    || !isTimestamp(value.created_at)
    || !Number.isInteger(value.current_version)
    || !Number.isInteger(value.check_count)
    || (value.current_version as number) < 0
    || (value.check_count as number) < 0
  ) {
    return null;
  }
  if (value.scope === "global" ? value.scope_id !== null : typeof value.scope_id !== "string") {
    return null;
  }
  return {
    id: value.id,
    name: value.name,
    scope: value.scope as MonitoringScope,
    scope_id: value.scope_id as string | null,
    enabled: value.enabled,
    created_at: value.created_at,
    current_version: value.current_version as number,
    check_count: value.check_count as number,
  };
}

export function monitoringPolicyListFromUnknown(value: unknown): MonitoringPolicy[] | null {
  if (!Array.isArray(value)) return null;
  const policies = value.map(monitoringPolicyFromUnknown);
  return policies.every((policy): policy is MonitoringPolicy => policy !== null)
    ? policies
    : null;
}

export function monitoringPolicyDetailFromUnknown(value: unknown): MonitoringPolicyDetail | null {
  const policy = monitoringPolicyFromUnknown(value);
  if (!policy || !isRecord(value)) return null;
  const checks = checksFromUnknown(value.checks);
  if (!checks || !Array.isArray(value.revisions)) return null;
  const revisions = value.revisions.map((item): MonitoringPolicyRevision | null => {
    if (!isRecord(item)) return null;
    const revisionChecks = checksFromUnknown(item.checks);
    if (
      typeof item.id !== "string"
      || !Number.isInteger(item.version)
      || (item.change_note !== null && typeof item.change_note !== "string")
      || (item.created_by !== null && typeof item.created_by !== "string")
      || !isTimestamp(item.created_at)
      || !revisionChecks
    ) {
      return null;
    }
    return {
      id: item.id,
      version: item.version as number,
      change_note: item.change_note as string | null,
      created_by: item.created_by as string | null,
      created_at: item.created_at,
      checks: revisionChecks,
    };
  });
  if (!revisions.every((revision): revision is MonitoringPolicyRevision => revision !== null)) {
    return null;
  }
  return { ...policy, checks, revisions };
}

export function formatMonitoringScope(scope: MonitoringScope): string {
  return {
    global: "Global",
    client: "Client",
    site: "Site",
    agent: "Agent",
  }[scope];
}

export function formatMonitoringTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unavailable";
  return `${new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(date)} UTC`;
}

export function formatCheckInterval(seconds: number): string {
  if (seconds % 3600 === 0) return `Every ${seconds / 3600}h`;
  if (seconds % 60 === 0) return `Every ${seconds / 60}m`;
  return `Every ${seconds}s`;
}

export function describeThreshold(threshold: MonitoringCheck["threshold"]): string {
  if (!threshold) return "State check";
  const operator = { gt: ">", gte: "â‰¥", lt: "<", lte: "â‰¤" }[threshold.op];
  return [
    threshold.warning === null ? null : `Warning ${operator} ${threshold.warning}`,
    threshold.critical === null ? null : `Critical ${operator} ${threshold.critical}`,
  ].filter(Boolean).join(" Â· ");
}

export function formatCheckType(type: CheckType): string {
  return type.replaceAll("_", " ");
}
