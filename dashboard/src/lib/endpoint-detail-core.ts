// SPDX-License-Identifier: AGPL-3.0-only

import type { EndpointTelemetrySample } from "@/lib/endpoint-detail";

export type MetricKey = "cpu_percent" | "mem_percent" | "disk_percent";

export function formatEndpointDateTime(value: string | null): string {
  if (!value) return "Never";
  return new Intl.DateTimeFormat("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(new Date(value));
}

export function formatEndpointUptime(seconds: number | null): string {
  if (seconds === null) return "Not reported";
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  return [days ? `${days}d` : "", hours ? `${hours}h` : "", `${minutes}m`].filter(Boolean).join(" ");
}

export function formatEndpointMetric(value: number | null): string {
  return value === null ? "Not reported" : `${Math.round(value)}%`;
}

/**
 * Render the agent build the server currently holds for an endpoint (issue
 * #179). The value is refreshed by the agent's heartbeat after an in-place
 * upgrade, so whatever the API returns is what an operator sees — this only
 * decides what to show when an endpoint has never reported one, and never
 * substitutes a remembered or inferred version.
 */
export function formatAgentVersion(
  value: string | null | undefined,
  fallback = "version unavailable",
): string {
  const trimmed = (value ?? "").trim();
  return trimmed === "" ? fallback : trimmed;
}

export function buildMetricPath(
  samples: EndpointTelemetrySample[],
  key: MetricKey,
  width: number,
  height: number,
): string {
  if (samples.length === 0) return "";
  const horizontalPadding = 18;
  const verticalPadding = 14;
  const drawableWidth = width - horizontalPadding * 2;
  const drawableHeight = height - verticalPadding * 2;
  let path = "";
  let drawing = false;

  samples.forEach((sample, index) => {
    const value = sample[key];
    if (value === null) {
      drawing = false;
      return;
    }
    const horizontalPosition = horizontalPadding + (samples.length === 1 ? drawableWidth / 2 : (index / (samples.length - 1)) * drawableWidth);
    const verticalPosition = verticalPadding + ((100 - Math.max(0, Math.min(100, value))) / 100) * drawableHeight;
    path += `${drawing ? " L" : "M"} ${horizontalPosition.toFixed(1)} ${verticalPosition.toFixed(1)}`;
    drawing = true;
  });
  return path;
}
