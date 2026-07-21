// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import { nodelinkApiRequest } from "@/lib/nodelink-api";

export type EndpointTelemetrySample = {
  ts: string;
  cpu_percent: number | null;
  mem_percent: number | null;
  disk_percent: number | null;
  uptime_seconds: number | null;
  logged_in_user: string | null;
};

export type EndpointDetailData = {
  id: string;
  hostname: string;
  os: string;
  os_version: string;
  agent_version: string;
  command_envelope_versions: string[];
  status: "pending" | "online" | "offline";
  trust_state: "active" | "quarantined" | "revoked";
  last_seen_at: string | null;
  enrolled_at: string;
  client_id: string;
  client_name: string;
  site_id: string;
  site_name: string;
  current_telemetry: EndpointTelemetrySample | null;
  telemetry: EndpointTelemetrySample[];
  telemetry_freshness: "current" | "stale" | "unavailable";
  stale_after_seconds: number;
  history_hours: number;
  history_limit: number;
  history_truncated: boolean;
};

export async function getEndpointDetail(
  sessionToken: string,
  endpointId: string,
  options: { historyHours?: number; historyLimit?: number } = {},
): Promise<EndpointDetailData> {
  const query = new URLSearchParams({
    history_hours: String(options.historyHours ?? 24),
    history_limit: String(options.historyLimit ?? 500),
  });
  return nodelinkApiRequest<EndpointDetailData>(
    `/api/v1/endpoints/${encodeURIComponent(endpointId)}?${query}`,
    { method: "GET", sessionToken },
  );
}
