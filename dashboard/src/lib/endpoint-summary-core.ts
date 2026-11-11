// SPDX-License-Identifier: AGPL-3.0-only

/** Presentation helpers for the endpoint detail Summary tab. */

import type { CommandStatus } from "./command-console-core.ts";
import type { EndpointDetailData, EndpointTelemetrySample } from "./endpoint-detail.ts";
import type { EndpointListItem } from "./endpoint-list.ts";

export type ReadingKey = "cpu_percent" | "mem_percent" | "disk_percent";

export type ReadingRange = { latest: number | null; low: number | null; high: number | null };

/** Latest reading plus the low and high across the loaded history window. */
export function readingRange(current: EndpointTelemetrySample | null, samples: readonly EndpointTelemetrySample[], key: ReadingKey): ReadingRange {
  const values = samples.map((sample) => sample[key]).filter((value): value is number => typeof value === "number" && Number.isFinite(value));
  return {
    latest: current?.[key] ?? null,
    low: values.length ? Math.min(...values) : null,
    high: values.length ? Math.max(...values) : null,
  };
}

export function formatHistoryWindow(hours: number): string {
  return hours < 24 ? `${hours} h` : hours === 24 ? "24 h" : `${hours / 24} days`;
}

export type CommandBadge = { tone: "ok" | "crit" | "info" | "off"; label: "Completed" | "Failed" | "Waiting" | "Running" | "Expired" };

/** Command status in the fixed status vocabulary; violet means in progress, never health. */
export function commandBadge(status: CommandStatus): CommandBadge {
  switch (status) {
    case "succeeded":
      return { tone: "ok", label: "Completed" };
    case "failed":
      return { tone: "crit", label: "Failed" };
    case "queued":
      return { tone: "info", label: "Waiting" };
    case "dispatched":
    case "running":
    case "result_pending":
      return { tone: "info", label: "Running" };
    case "expired":
      return { tone: "off", label: "Expired" };
  }
}

/** The list-shaped record the shared device status reads, from a detail record. */
export function detailAsListItem(detail: EndpointDetailData): EndpointListItem {
  const sample = detail.current_telemetry;
  return {
    id: detail.id,
    hostname: detail.hostname,
    os: detail.os,
    os_version: detail.os_version,
    agent_version: detail.agent_version,
    status: detail.status,
    last_seen_at: detail.last_seen_at,
    client_id: detail.client_id,
    client_name: detail.client_name,
    site_id: detail.site_id,
    site_name: detail.site_name,
    cpu_percent: sample?.cpu_percent ?? null,
    mem_percent: sample?.mem_percent ?? null,
    disk_percent: sample?.disk_percent ?? null,
    logged_in_user: sample?.logged_in_user ?? null,
  };
}

export const TRUST_LABELS: Record<EndpointDetailData["trust_state"], { tone: "ok" | "warn" | "crit"; label: string; detail: string }> = {
  active: { tone: "ok", label: "Verified", detail: "Accepts only commands signed by NodeLink." },
  quarantined: { tone: "warn", label: "Needs review", detail: "Quarantined: restore trust before sending it commands." },
  revoked: { tone: "crit", label: "Revoked", detail: "Its credentials were revoked; it can no longer receive commands." },
};
