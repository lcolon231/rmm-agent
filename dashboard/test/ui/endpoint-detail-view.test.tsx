// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { render, screen, within } from "@testing-library/react";
import { AppRouterContext, type AppRouterInstance } from "next/dist/shared/lib/app-router-context.shared-runtime";

import { EndpointDetailView } from "@/components/endpoint-detail-view";
import type { CommandHistoryItem } from "@/lib/command-console-core";
import type { DashboardOperator } from "@/lib/dashboard-auth-core";
import type { DeviceStatus } from "@/lib/device-status-core";
import type { EndpointDetailData } from "@/lib/endpoint-detail";

const now = "2026-11-11T12:00:00Z";
const operator: DashboardOperator = { id: "op-1", email: "tech@clinic.example", role: "operator", disabled: false };
const readonly: DashboardOperator = { ...operator, role: "readonly" };

function endpoint(overrides: Partial<EndpointDetailData> = {}): EndpointDetailData {
  return {
    id: "agent-1", hostname: "PHX-FD-02", os: "Windows", os_version: "11 Pro", agent_version: "1.4.0",
    command_envelope_versions: [], supported_capabilities: [], status: "online", trust_state: "active",
    last_seen_at: "2026-11-11T11:58:00Z", enrolled_at: "2026-01-02T09:00:00Z", client_id: "c1", client_name: "Lakeshore",
    site_id: "s1", site_name: "Main office", script_execution_allowed: true,
    current_telemetry: { ts: "2026-11-11T11:58:00Z", cpu_percent: 43, mem_percent: 71, disk_percent: 93, uptime_seconds: 3600, logged_in_user: "frontdesk" },
    telemetry: [
      { ts: "2026-11-11T10:00:00Z", cpu_percent: 12, mem_percent: 60, disk_percent: 92, uptime_seconds: 1, logged_in_user: null },
      { ts: "2026-11-11T11:58:00Z", cpu_percent: 43, mem_percent: 71, disk_percent: 93, uptime_seconds: 3600, logged_in_user: "frontdesk" },
    ],
    telemetry_freshness: "current", stale_after_seconds: 600, history_hours: 24, history_limit: 500, history_truncated: false,
    ...overrides,
  };
}

const healthy: DeviceStatus = { tone: "ok", label: "Healthy", reason: "No open problems" };
const warning: DeviceStatus = { tone: "warn", label: "Warning", reason: "Disk at 93%" };

function show(props: Partial<Parameters<typeof EndpointDetailView>[0]> = {}) {
  const router = { push() {}, refresh() {}, replace() {}, back() {}, forward() {}, prefetch() {} };
  return render(
    <AppRouterContext.Provider value={router as unknown as AppRouterInstance}>
      <EndpointDetailView endpoint={endpoint()} operator={operator} status={healthy} commands={[]} tab="summary" now={now} {...props} />
    </AppRouterContext.Provider>,
  );
}

test("each pie chart has an accessible name, and the exact values stay available as a table", () => {
  show();
  assert.ok(screen.getByRole("img", { name: "Processor: 43% in use" }));
  assert.ok(screen.getByRole("img", { name: "Memory: 71% in use" }));
  assert.ok(screen.getByRole("img", { name: "Disk: 93% in use" }));
  assert.ok(screen.getByText("24 h low 92% · high 93%"));
  assert.equal(within(screen.getByRole("table", { name: "Readings for each check-in" })).getAllByRole("row").length, 3);
});

test("a missing reading is said, not drawn as an empty 0% pie", () => {
  show({ endpoint: endpoint({ current_telemetry: null, telemetry: [], telemetry_freshness: "unavailable" }) });
  assert.ok(screen.getByRole("img", { name: "Disk: no reading" }));
  assert.match(screen.getAllByRole("status").map((node) => node.textContent).join(" "), /No readings have been reported yet/);
});

test("an at-risk device gets a banner in its status tone with advice; a healthy one does not", () => {
  const { unmount } = show({ status: warning });
  assert.match(screen.getByText(/Warning: Disk at 93%/).parentElement?.textContent ?? "", /Keep an eye on it/);
  unmount();
  show();
  assert.equal(screen.queryByText(/Keep an eye on it/), null);
});

test("readonly operators and untrusted devices are not offered the command action", () => {
  const { unmount } = show({ operator: readonly });
  assert.equal(screen.queryByRole("link", { name: /Restart or run a command/ }), null);
  unmount();
  show({ endpoint: endpoint({ trust_state: "revoked" }) });
  assert.equal(screen.queryByRole("link", { name: /Restart or run a command/ }), null);
  assert.ok(screen.getByText(/can no longer receive commands/));
});

test("tabs are route links; the current one is marked", (t) => {
  // The remote desktop panel checks availability on mount; never reach a live API.
  t.mock.method(globalThis, "fetch", async () => Response.json({ can_launch: false, message: "Not configured" }));
  show({ tab: "remote" });
  const nav = screen.getByRole("navigation", { name: "Device sections" });
  const links = within(nav).getAllByRole("link");
  assert.deepEqual(links.map((link) => [link.textContent, link.getAttribute("href"), link.getAttribute("aria-current")]), [
    ["Summary", "/endpoints/agent-1", null],
    ["Inventory", "/endpoints/agent-1/inventory", null],
    ["Commands", "/endpoints/agent-1/commands", null],
    ["Remote access", "/endpoints/agent-1?tab=remote", "page"],
  ]);
});

test("recent commands use the fixed status words and link to each command", () => {
  const command = { id: "cmd-12345678-abcd", kind: "collect_inventory", status: "result_pending", created_at: "2026-11-11T11:55:00Z" } as unknown as CommandHistoryItem;
  show({ commands: [command] });
  const card = screen.getByRole("region", { name: "Recent actions on this device" });
  const link = within(card).getByRole("link", { name: /Collect inventory/ });
  assert.equal(link.getAttribute("href"), "/endpoints/agent-1/commands/cmd-12345678-abcd");
  assert.match(link.textContent ?? "", /Running/);
});

test("failed command history says so instead of claiming there are no commands", () => {
  show({ commands: null });
  const card = screen.getByRole("region", { name: "Recent actions on this device" });
  assert.match(within(card).getByRole("alert").textContent ?? "", /could not be loaded\. Nothing was changed\./);
  assert.equal(within(card).queryByText(/No commands have been sent/), null);
});
