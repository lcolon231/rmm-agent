// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { beforeEach, mock, test } from "node:test";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { AppRouterContext } from "next/dist/shared/lib/app-router-context.shared-runtime";
import type { ReactElement } from "react";

import type { DashboardSessionState } from "@/lib/dashboard-auth-core";
import type { EndpointListItem } from "@/lib/endpoint-list";

class NavigationSignal extends Error {}

let session: DashboardSessionState = { kind: "anonymous" };
const listCalls: Array<Record<string, unknown>> = [];
let alertsFail = false;
let listFail = false;

function item(overrides: Partial<EndpointListItem>): EndpointListItem {
  return {
    id: "a1", hostname: "PHX-FD-02", os: "Windows", os_version: "11 Pro", agent_version: "1.4.0", status: "online",
    last_seen_at: new Date().toISOString(), client_id: "c1", client_name: "Lakeshore", site_id: "s1", site_name: "Main office",
    cpu_percent: 10, mem_percent: 20, disk_percent: 30, logged_in_user: "frontdesk", ...overrides,
  };
}

const ITEMS = [
  item({ id: "ok", hostname: "A-HEALTHY" }),
  item({ id: "off", hostname: "B-OFFLINE", status: "offline" }),
  item({ id: "crit", hostname: "C-CRITICAL" }),
  item({ id: "warn", hostname: "=D-WARN", disk_percent: 95 }),
];

mock.module("@/lib/dashboard-session", { namedExports: { getDashboardSession: async () => session } });
mock.module("@/lib/endpoint-list", {
  namedExports: {
    getEndpointList: async (_token: string, options: Record<string, unknown>) => {
      listCalls.push(options);
      if (listFail && options.pageSize !== 1) throw new Error("down");
      const totals: Record<string, number> = { online: 30, offline: 4, pending: 2 };
      const total = options.status ? totals[options.status as string] : 36;
      return { items: options.pageSize === 1 ? [] : ITEMS, page: 1, page_size: 25, total };
    },
  },
});
mock.module("@/lib/monitoring", {
  namedExports: {
    getMonitoringAlerts: async () => {
      if (alertsFail) throw new Error("down");
      return [{ agent_id: "crit", state: "open", last_result_status: "critical" }];
    },
  },
});
mock.module("next/navigation", {
  namedExports: {
    redirect: (to: string) => { throw new NavigationSignal(`redirect:${to}`); },
    useRouter: () => router,
  },
});

const router = { push: mock.fn(), refresh: mock.fn(), replace: mock.fn(), back: mock.fn(), forward: mock.fn(), prefetch: mock.fn() };
const { default: EndpointsPage } = await import("@/app/endpoints/page");

const operator = { id: "op-1", email: "tech@example.com", role: "operator" };
const signedIn = { kind: "authenticated", operator, sessionToken: "t" } as DashboardSessionState;

async function visit(query: Record<string, string> = {}) {
  const element = (await EndpointsPage({ searchParams: Promise.resolve(query) })) as ReactElement;
  return render(<AppRouterContext.Provider value={router as never}>{element}</AppRouterContext.Provider>);
}

function bodyRows() {
  return within(screen.getByRole("table", { name: "Devices" })).getAllByRole("row").slice(1);
}

beforeEach(() => {
  session = signedIn;
  listCalls.length = 0;
  alertsFail = false;
  listFail = false;
});

test("an anonymous visitor is redirected to sign in", async () => {
  session = { kind: "anonymous" };
  await assert.rejects(EndpointsPage({ searchParams: Promise.resolve({}) }), { message: "redirect:/login" });
});

test("rows on the page are ordered critical, offline, warning, healthy", async () => {
  await visit();
  assert.deepEqual(bodyRows().map((row) => row.getAttribute("aria-label")), [
    "Preview C-CRITICAL",
    "Preview B-OFFLINE",
    "Preview =D-WARN",
    "Preview A-HEALTHY",
  ]);
  assert.ok(screen.getByText(/most urgent first on this page/), "the footer does not claim a global order");
});

test("there is no per-row delete; revoking lives behind Enrollment", async (t) => {
  const confirm = t.mock.fn(() => true);
  const original = window.confirm;
  window.confirm = confirm;
  t.after(() => { window.confirm = original; });
  await visit();
  assert.equal(screen.queryByRole("button", { name: /delete/i }), null);
  fireEvent.click(bodyRows()[0]);
  assert.equal(confirm.mock.callCount(), 0, "no browser confirm dialog anywhere on the list");
});

test("a row opens the preview drawer, which links to the device and its command form", async () => {
  await visit();
  fireEvent.keyDown(bodyRows()[0], { key: "Enter" });
  const drawer = screen.getByRole("dialog", { name: "C-CRITICAL" });
  assert.match(within(drawer).getByRole("status").textContent ?? "", /Critical1 critical alert open\./);
  assert.equal(within(drawer).getByRole("link", { name: "Open device" }).getAttribute("href"), "/endpoints/crit");
  assert.equal(within(drawer).getByRole("link", { name: /Restart or run a command/ }).getAttribute("href"), "/endpoints/crit/commands");
});

test("status chips are links that keep the search and show server totals", async () => {
  await visit({ search: "PHX", status: "offline" });
  const group = screen.getByRole("group", { name: "Filter by status" });
  const offline = within(group).getByRole("link", { name: /Offline/ });
  assert.equal(offline.getAttribute("aria-current"), "true");
  assert.match(offline.textContent ?? "", /4/);
  assert.equal(within(group).getByRole("link", { name: /Online/ }).getAttribute("href"), "/endpoints?status=online&search=PHX");
  for (const call of listCalls) assert.equal(call.search, "PHX", "counts honour the search too");
});

test("if alerts cannot be loaded the page says nothing is shown as critical", async () => {
  alertsFail = true;
  await visit();
  assert.match(screen.getByText(/Monitoring alerts could not be loaded/).textContent ?? "", /no device is shown as critical/);
  assert.equal(bodyRows()[0].getAttribute("aria-label"), "Preview B-OFFLINE");
});

test("a failed list shows an error that says nothing was changed, and no rows", async () => {
  listFail = true;
  await visit();
  assert.equal(screen.queryByRole("table"), null);
  assert.match(screen.getByRole("alert").textContent ?? "", /could not be loaded\. Nothing was changed\./);
});

test("readonly operators are not offered Add a device", async () => {
  session = { ...signedIn, operator: { ...operator, role: "readonly" } } as DashboardSessionState;
  await visit();
  assert.equal(screen.queryByRole("link", { name: "Add a device" }), null);
});
