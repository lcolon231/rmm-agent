// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Pure presentation logic for inventory and change views.
 *
 * The rule that runs through this file: a section that could not be collected
 * must never render like a section that was collected and found empty. Ten
 * sections of security-relevant evidence are only useful if "we did not look"
 * is visually distinct from "we looked and there was nothing".
 */

export type InventorySectionStatus =
  | "ok"
  | "partial"
  | "unavailable"
  | "unsupported"
  | "permission_denied";

export type InventorySectionRecord = {
  id: string;
  agent_id: string;
  section: string;
  status: InventorySectionStatus;
  schema_version: number;
  content_hash: string;
  byte_size: number;
  payload: Record<string, unknown>;
  collected_at: string;
  received_at: string;
};

export type InventoryRecord = {
  agent_id: string;
  sections: InventorySectionRecord[];
  missing_sections: string[];
};

export type FieldChange = { field: string; from: unknown; to: unknown };

export type ListChange = {
  added: unknown[];
  removed: unknown[];
  changed: { identity: Record<string, unknown> | null; changes: FieldChange[] }[];
};

export type InventoryDiffRecord = {
  agent_id: string;
  section: string;
  comparable: boolean;
  before: InventorySectionRecord | null;
  after: InventorySectionRecord | null;
  diff: { field_changes: FieldChange[]; list_changes: Record<string, ListChange> };
  summary: {
    fields_changed?: number;
    items_added?: number;
    items_removed?: number;
    items_changed?: number;
  };
};

const SECTION_LABELS: Record<string, string> = {
  system: "System",
  cpu: "Processor",
  memory: "Memory",
  storage: "Storage",
  network: "Network",
  installed_software: "Installed software",
  security_defender: "Defender",
  security_bitlocker: "BitLocker",
  security_secure_boot: "Secure Boot",
  security_tpm: "TPM",
  local_administrators: "Local administrators",
  windows_updates: "Windows Updates",
};

export function sectionLabel(section: string): string {
  return SECTION_LABELS[section] ?? section.replaceAll("_", " ");
}

/** Tone for a section status. */
export type StatusTone = "verified" | "failed" | "unknown";

/**
 * How a section status should read.
 *
 * `partial` and `unsupported` are *not* failures — a bounded list and a machine
 * that genuinely lacks a feature are both correct outcomes — but neither is a
 * clean bill of health either, so both render as `unknown` rather than green.
 * `permission_denied` is a failure: it is a fixable deployment problem, and an
 * unread BitLocker state must never sit quietly next to a healthy one.
 */
export function statusTone(status: InventorySectionStatus): StatusTone {
  switch (status) {
    case "ok":
      return "verified";
    case "permission_denied":
    case "unavailable":
      return "failed";
    default:
      return "unknown";
  }
}

export function statusLabel(status: InventorySectionStatus): string {
  return {
    ok: "Collected",
    partial: "Partial",
    unavailable: "Unavailable",
    unsupported: "Not supported",
    permission_denied: "Permission denied",
  }[status];
}

/** One-line explanation of what a status means for the data shown beside it. */
export function statusExplanation(status: InventorySectionStatus): string {
  switch (status) {
    case "ok":
      return "Collected completely at the time shown.";
    case "partial":
      return "Collected, but bounded — some rows were trimmed and are not shown.";
    case "unavailable":
      return "The endpoint supports this but collection failed. Values shown, if any, may be incomplete.";
    case "unsupported":
      return "This endpoint cannot report this. Absence here is not evidence of a problem.";
    case "permission_denied":
      return "The agent lacks the rights to read this. This is not evidence that nothing is configured — it means nobody looked.";
  }
}

export function formatInventoryTimestamp(value: string | null, fallback = "Never"): string {
  if (!value) return fallback;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return fallback;
  return new Intl.DateTimeFormat("en-US", {
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    month: "short",
    timeZone: "UTC",
    timeZoneName: "short",
    year: "numeric",
  }).format(date);
}

/**
 * The gap between collection on the endpoint and receipt by the server.
 *
 * Surfaced because a large gap means a queued or clock-skewed endpoint, and a
 * technician needs to know that before trusting the values as current.
 */
export function collectionLagSeconds(
  record: Pick<InventorySectionRecord, "collected_at" | "received_at">,
): number | null {
  const collected = new Date(record.collected_at).getTime();
  const received = new Date(record.received_at).getTime();
  if (Number.isNaN(collected) || Number.isNaN(received)) return null;
  return Math.round((received - collected) / 1000);
}

/** True when the lag is large enough to caveat the values shown. */
export function hasSuspiciousLag(seconds: number | null, thresholdSeconds = 3600): boolean {
  return seconds !== null && Math.abs(seconds) >= thresholdSeconds;
}

export function formatLag(seconds: number): string {
  const absolute = Math.abs(seconds);
  if (absolute < 60) return `${absolute}s`;
  if (absolute < 3600) return `${Math.floor(absolute / 60)}m`;
  if (absolute < 86_400) return `${Math.floor(absolute / 3600)}h`;
  return `${Math.floor(absolute / 86_400)}d`;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

/** Flatten a payload into ordered rows, keeping list fields out of the table. */
export function payloadRows(payload: Record<string, unknown>): { key: string; value: string }[] {
  return Object.keys(payload)
    .filter((key) => !Array.isArray(payload[key]))
    .sort()
    .map((key) => ({ key, value: formatValue(payload[key]) }));
}

/** List fields in a payload, in a stable order. */
export function payloadLists(
  payload: Record<string, unknown>,
): { key: string; items: unknown[] }[] {
  return Object.keys(payload)
    .filter((key) => Array.isArray(payload[key]))
    .sort()
    .map((key) => ({ key, items: payload[key] as unknown[] }));
}

export function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value)) return value.length === 0 ? "(none)" : value.map(formatValue).join(", ");
  if (typeof value === "object") {
    return Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== null && item !== undefined)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => `${key}: ${formatValue(item)}`)
      .join(" · ");
  }
  return String(value);
}

/** A short human description of one list element, for diff rows. */
export function describeItem(item: unknown): string {
  if (item === null || typeof item !== "object") return formatValue(item);
  const record = item as Record<string, unknown>;
  for (const key of ["name", "mount_point", "model", "slot", "mac_address"]) {
    const candidate = record[key];
    if (typeof candidate === "string" && candidate) {
      const version = record.version;
      return typeof version === "string" && version ? `${candidate} ${version}` : candidate;
    }
  }
  return formatValue(item);
}

export function diffIsEmpty(diff: InventoryDiffRecord["diff"] | null | undefined): boolean {
  if (!diff) return true;
  return (
    (diff.field_changes ?? []).length === 0 &&
    Object.keys(diff.list_changes ?? {}).length === 0
  );
}

/** Total number of individual changes, for a headline count. */
export function totalChanges(summary: InventoryDiffRecord["summary"]): number {
  return (
    (summary.fields_changed ?? 0) +
    (summary.items_added ?? 0) +
    (summary.items_removed ?? 0) +
    (summary.items_changed ?? 0)
  );
}

/** Validate a section name from the URL against what the server reported. */
export function resolveSection(
  candidate: string | undefined,
  known: readonly string[],
): string | null {
  if (!candidate) return null;
  return known.includes(candidate) ? candidate : null;
}
