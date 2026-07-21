// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  buildMetricPath,
  formatEndpointDateTime,
  formatEndpointMetric,
  formatEndpointUptime,
} from "../src/lib/endpoint-detail-core.ts";
import type { EndpointTelemetrySample } from "../src/lib/endpoint-detail.ts";

function sample(ts: string, cpuPercent: number | null): EndpointTelemetrySample {
  return {
    ts,
    cpu_percent: cpuPercent,
    mem_percent: 50,
    disk_percent: 70,
    uptime_seconds: 60,
    logged_in_user: null,
  };
}

test("formats telemetry timestamps with an explicit UTC timezone", () => {
  const formatted = formatEndpointDateTime("2026-07-21T05:00:00Z");
  assert.match(formatted, /UTC/);
  assert.match(formatted, /Jul 21, 2026/);
});

test("formats unavailable metrics and bounded uptime clearly", () => {
  assert.equal(formatEndpointMetric(null), "Not reported");
  assert.equal(formatEndpointMetric(49.6), "50%");
  assert.equal(formatEndpointUptime(null), "Not reported");
  assert.equal(formatEndpointUptime(183_660), "2d 3h 1m");
});

test("telemetry paths break across unsupported samples and clamp values", () => {
  const path = buildMetricPath(
    [
      sample("2026-07-21T05:00:00Z", -10),
      sample("2026-07-21T05:01:00Z", null),
      sample("2026-07-21T05:02:00Z", 110),
    ],
    "cpu_percent",
    300,
    100,
  );
  assert.equal((path.match(/M/g) ?? []).length, 2);
  assert.doesNotMatch(path, /-/);
});
