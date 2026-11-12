// SPDX-License-Identifier: AGPL-3.0-only
// The Overview page loads seven sources in parallel. These tests pin that a
// failing source degrades only its own card, and that scope is never widened.
import assert from "node:assert/strict";
import { beforeEach, mock, test } from "node:test";
import { render, screen, within } from "@testing-library/react";
import type { ReactNode } from "react";

import type { DashboardSessionState } from "@/lib/dashboard-auth-core";
import type { EndpointListItem } from "@/lib/endpoint-list";

class NavigationSignal extends Error {}

let session: DashboardSessionState = { kind: "anonymous" };

function item(overrides: Partial<EndpointListItem>): EndpointListItem {
  return {
    id: "a1", hostname: "PHX-FD-02", os: "Windows", os_version: "11", agent_version: "1.4.0", status: "online",
    last_seen_at: new Date().toISOString(), client_id: "c1", client_name: "Lakeshore", site_id: "s1", site_name: "Main office",
    cpu_percent: 10, mem_percent: 20, disk_percent: 30, logged_in_user: null, ...overrides,
  };
}

const page = (items: EndpointListItem[], total = items.length) => ({ items, page: 1, page_size: 25, total });

type Loader = (...args: unknown[]) => Promise<unknown>;
const loaders: Record<string, Loader> = {};
const endpointCalls: unknown[] = [];
const fail = async () => { throw new Error("down"); };

function reset() {
  endpointCalls.length = 0;
  loaders.navigation = async () => ({ items: [{ id: "c1", name: "Lakeshore", sites: [{ id: "s1", client_id: "c1", name: "Main office", endpoint_count: 3 }] }], truncated: false });
  loaders.endpoints = async (_token, options) => {
    const status = (options as { status?: string }).status;
    if (status === "offline") return page([item({ id: "off", hostname: "PHX-LAB-01", status: "offline" })], 1);
    if (status === "online") return page([item({ id: "a1" }), item({ id: "hot", hostname: "PHX-RX-03", disk_percent: 97 })], 2);
    return page([item({ id: "a1" }), item({ id: "hot", hostname: "PHX-RX-03", disk_percent: 97 })], 3);
  };
  loaders.alerts = async () => [{ agent_id: "a1", state: "open", last_result_status: "critical" }];
  loaders.compliance = async () => ({ total_endpoints: 3, compliant: 2, non_compliant: 1, stale: 0, unknown: 0, exempt: 0, total_approved_missing: 1, truncated: false });
  loaders.approvals = async () => [];
  loaders.audit = async () => ({ items: [] });
}

mock.module("@/lib/dashboard-session", { namedExports: { getDashboardSession: async () => session } });
mock.module("@/lib/client-navigation", { namedExports: { getClientNavigation: (...args: unknown[]) => loaders.navigation(...args) } });
mock.module("@/lib/endpoint-list", {
  namedExports: { getEndpointList: (...args: unknown[]) => { endpointCalls.push(args[1]); return loaders.endpoints(...args); } },
});
mock.module("@/lib/monitoring", { namedExports: { getMonitoringAlerts: (...args: unknown[]) => loaders.alerts(...args) } });
mock.module("@/lib/patch-compliance", { namedExports: { getComplianceSummary: (...args: unknown[]) => loaders.compliance(...args) } });
mock.module("@/lib/approvals", { namedExports: { getApprovalRequests: (...args: unknown[]) => loaders.approvals(...args) } });
mock.module("@/lib/audit", { namedExports: { getAuditEventPage: (...args: unknown[]) => loaders.audit(...args) } });
mock.module("@/components/shell/app-shell", {
  namedExports: {
    AppShell: ({ children, selectionError, alertCount }: { children: ReactNode; selectionError: boolean; alertCount?: number }) => (
      <div data-selection-error={String(selectionError)} data-alert-count={String(alertCount)}>{children}</div>
    ),
  },
});
mock.module("next/navigation", {
  namedExports: { redirect: (to: string) => { throw new NavigationSignal(`redirect:${to}`); } },
});

const { default: Home } = await import("@/app/page");

const signedIn = { kind: "authenticated", operator: { id: "op-1", email: "tech@example.com", role: "operator" }, sessionToken: "t" } as DashboardSessionState;

function visit(query: { client?: string; site?: string } = {}) {
  return Home({ searchParams: Promise.resolve(query) });
}

beforeEach(() => {
  session = signedIn;
  reset();
});

test("an anonymous visitor is redirected to sign in", async () => {
  session = { kind: "anonymous" };
  await assert.rejects(visit(), { message: "redirect:/login" });
});

test("needs attention lists at-risk devices only, most urgent first, linking to each device", async () => {
  render(await visit());
  const card = screen.getByRole("region", { name: "Needs attention" });
  const links = within(card).getAllByRole("link").filter((link) => link.getAttribute("href")?.startsWith("/endpoints/"));
  assert.deepEqual(links.map((link) => link.getAttribute("href")), ["/endpoints/a1", "/endpoints/off", "/endpoints/hot"]);
  assert.match(links[0].textContent ?? "", /Critical.*1 critical alert open/);
  assert.match(links[2].textContent ?? "", /Disk at 97%/);
});

test("counts come from the server's totals, not from one page of devices", async () => {
  render(await visit());
  const tile = screen.getByText("Devices online").closest("div")!;
  assert.match(tile.textContent ?? "", /Devices online2of 3 · 1 offline/);
});

test("one failing source degrades only its own card", async () => {
  loaders.compliance = fail;
  loaders.approvals = fail;
  render(await visit());
  const patch = screen.getByRole("region", { name: "Patch compliance" });
  assert.match(within(patch).getByRole("alert").textContent ?? "", /could not be loaded\. Nothing was changed\./);
  assert.ok(within(screen.getByRole("region", { name: "Waiting for your approval" })).getByRole("alert"));
  assert.equal(within(screen.getByRole("region", { name: "Needs attention" })).queryByRole("alert"), null, "devices still render");
});

test("an unknown client is sent to the API as asked, never widened to every client", async () => {
  const { container } = render(await visit({ client: "c-not-mine" }));
  assert.ok(endpointCalls.length > 0);
  for (const options of endpointCalls) assert.equal((options as { clientId?: string }).clientId, "c-not-mine");
  assert.equal(container.querySelector("[data-selection-error]")?.getAttribute("data-selection-error"), "true");
});

test("a scoped view says alerts and activity are across all clients", async () => {
  render(await visit({ client: "c1" }));
  assert.ok(screen.getByRole("heading", { level: 1, name: "Overview" }));
  assert.ok(within(screen.getByRole("region", { name: "Open alerts by severity" })).getByText("Across all clients"));
  assert.match(screen.getByRole("region", { name: "Recent activity" }).textContent ?? "", /Across all clients\./);
});

test("the bell count is the open alert total, and absent when alerts failed", async () => {
  let view = render(await visit());
  assert.equal(view.container.querySelector("[data-alert-count]")?.getAttribute("data-alert-count"), "1");
  view.unmount();
  loaders.alerts = fail;
  view = render(await visit());
  assert.equal(view.container.querySelector("[data-alert-count]")?.getAttribute("data-alert-count"), "undefined");
});
