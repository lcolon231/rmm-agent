// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { beforeEach, mock, test, type TestContext } from "node:test";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";

import type { DashboardOperator } from "@/lib/dashboard-auth-core";

// next/image is CommonJS and arrives as a module object under tsx; a plain
// img keeps the test about the shell, not the image optimizer.
mock.module("next/image", {
  // eslint-disable-next-line @next/next/no-img-element -- test stand-in for next/image
  defaultExport: ({ alt, src }: { alt: string; src: string }) => <img alt={alt} src={src} />,
});
const { AppShell } = await import("@/components/shell/app-shell");
const { activeHref, NAV_GROUPS, visibleGroups } = await import("@/components/shell/nav-groups");

const admin: DashboardOperator = { id: "op-1", email: "a.rivera@clinic.example", role: "admin", disabled: false };
const readonly: DashboardOperator = { ...admin, id: "op-2", email: "viewer@clinic.example", role: "readonly" };

type Integrity = { chain: string; last_anchor_at: string | null } | "throw" | number;

function stubFetch(t: TestContext, { integrity = { chain: "intact", last_anchor_at: null }, unread = 0 }: { integrity?: Integrity; unread?: number } = {}) {
  const calls: Array<{ url: string; method: string }> = [];
  t.mock.method(globalThis, "fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, method: init?.method ?? "GET" });
    if (url === "/api/audit/integrity") {
      if (integrity === "throw") throw new TypeError("network down");
      if (typeof integrity === "number") return new Response("{}", { status: integrity });
      return Response.json(integrity);
    }
    if (url === "/api/support/unread-count") return Response.json({ unread });
    return new Response(null, { status: 204 });
  });
  return calls;
}

function renderShell(operator: DashboardOperator = admin, activePath = "/endpoints") {
  return render(
    <AppShell activePath={activePath} navigation={{ items: [], truncated: false }} navigationError={false} operator={operator}>
      <p>Page body</p>
    </AppShell>,
  );
}

/** The full sidebar is rendered once for wide screens; read nav from it. */
function fullNav() {
  return within(screen.getByRole("complementary", { name: "Sidebar" })).getAllByRole("navigation", { name: "Primary" })[1];
}

beforeEach(() => {
  window.sessionStorage.clear();
  window.localStorage.clear();
});

test("admin-only destinations are hidden from other roles", () => {
  const forReadonly = visibleGroups("readonly").flatMap((group) => group.items.map((item) => item.label));
  assert.ok(!forReadonly.includes("Operators"));
  assert.ok(!forReadonly.includes("Break-glass"));
  const forAdmin = visibleGroups("admin").flatMap((group) => group.items.map((item) => item.label));
  assert.ok(forAdmin.includes("Operators") && forAdmin.includes("Break-glass"));
});

test("exactly one destination is active, by longest match", () => {
  const groups = visibleGroups("admin");
  assert.equal(activeHref("/security/break-glass", groups), "/security/break-glass");
  assert.equal(activeHref("/security", groups), "/security");
  assert.equal(activeHref("/endpoints/abc/commands/1", groups), "/endpoints");
  assert.equal(activeHref("/", groups), "/");
  assert.equal(activeHref("/endpointsx", groups), null, "a prefix without a slash is not a match");
  assert.equal(NAV_GROUPS.length, 7);
});

test("the current group is open and marks one page; other groups start closed", (t) => {
  stubFetch(t);
  renderShell(admin, "/security/break-glass");
  const nav = fullNav();
  const current = within(nav).getAllByRole("link").filter((link) => link.getAttribute("aria-current") === "page");
  assert.deepEqual(current.map((link) => link.textContent), ["Break-glass"]);
  assert.equal(within(nav).getByRole("button", { name: /Administration/ }).getAttribute("aria-expanded"), "true");
  assert.equal(within(nav).getByRole("button", { name: /Devices/ }).getAttribute("aria-expanded"), "false");
});

test("readonly operators never see admin-only links in the sidebar", (t) => {
  stubFetch(t);
  renderShell(readonly, "/security");
  const nav = fullNav();
  assert.equal(within(nav).queryByRole("link", { name: "Operators" }), null);
  assert.equal(within(nav).queryByRole("link", { name: "Break-glass" }), null);
});

test("opening a group is remembered for the next visit", async (t) => {
  stubFetch(t);
  const { unmount } = renderShell();
  fireEvent.click(within(fullNav()).getByRole("button", { name: /Patching/ }));
  assert.deepEqual(JSON.parse(window.localStorage.getItem("nodelink.nav-groups")!), { patching: true });
  unmount();
  renderShell();
  await waitFor(() => assert.equal(within(fullNav()).getByRole("button", { name: /Patching/ }).getAttribute("aria-expanded"), "true"));
});

test("integrity reads 'checking' until verified, then intact, with no page-view audit claim", async (t) => {
  stubFetch(t, { integrity: { chain: "intact", last_anchor_at: null } });
  renderShell();
  const footer = screen.getByRole("contentinfo");
  assert.match(footer.textContent ?? "", /Checking audit record/);
  assert.doesNotMatch(footer.textContent ?? "", /intact/);
  await waitFor(() => assert.match(footer.textContent ?? "", /Audit record intact/));
  assert.match(footer.textContent ?? "", /No integrity anchor yet/);
  assert.match(footer.textContent ?? "", /Signed in as a\.rivera@clinic\.example/);
  assert.doesNotMatch(footer.textContent ?? "", /recorded/i, "page views are not audited, so the footer must not say they are");
});

test("a broken chain is raised as an alert in the footer and the sidebar", async (t) => {
  stubFetch(t, { integrity: { chain: "failed", last_anchor_at: "2026-11-11T09:40:00Z" } });
  renderShell();
  await waitFor(() => assert.ok(screen.getAllByRole("alert").length >= 2));
  for (const alert of screen.getAllByRole("alert")) assert.equal(alert.textContent, "Audit record check failed");
  assert.ok(screen.getAllByRole("link", { name: "Open audit log" }).length >= 1);
});

test("an unreachable or refused check reads 'not verified', never intact", async (t) => {
  for (const integrity of ["throw", 401, 503] as const) {
    window.sessionStorage.clear();
    stubFetch(t, { integrity });
    const { unmount } = renderShell();
    const footer = screen.getByRole("contentinfo");
    await waitFor(() => assert.match(footer.textContent ?? "", /Audit record not verified/, `case ${integrity}`));
    assert.doesNotMatch(footer.textContent ?? "", /intact/);
    unmount();
    t.mock.restoreAll();
  }
});

test("only an intact result is reused from the tab cache; a failure is always re-checked", async (t) => {
  let calls = stubFetch(t, { integrity: { chain: "intact", last_anchor_at: null } });
  let view = renderShell();
  await waitFor(() => assert.match(screen.getByRole("contentinfo").textContent ?? "", /intact/));
  view.unmount();
  t.mock.restoreAll();

  calls = stubFetch(t, { integrity: { chain: "failed", last_anchor_at: null } });
  view = renderShell();
  await waitFor(() => assert.match(screen.getByRole("contentinfo").textContent ?? "", /intact/));
  assert.equal(calls.filter((call) => call.url === "/api/audit/integrity").length, 0, "fresh intact result reused within a minute");
  view.unmount();
  t.mock.restoreAll();

  window.sessionStorage.setItem("nodelink.audit-integrity", JSON.stringify({ at: Date.now(), summary: { chain: "failed", last_anchor_at: null } }));
  calls = stubFetch(t, { integrity: { chain: "failed", last_anchor_at: null } });
  renderShell();
  await waitFor(() => assert.ok(screen.getAllByRole("alert").length >= 1));
  assert.equal(calls.filter((call) => call.url === "/api/audit/integrity").length, 1, "a stored failure is never trusted; it is fetched again");
});

test("a stale intact result is not reused", async (t) => {
  window.sessionStorage.setItem("nodelink.audit-integrity", JSON.stringify({ at: Date.now() - 61_000, summary: { chain: "intact", last_anchor_at: null } }));
  const calls = stubFetch(t, { integrity: { chain: "failed", last_anchor_at: null } });
  renderShell();
  await waitFor(() => assert.ok(screen.getAllByRole("alert").length >= 1));
  assert.equal(calls.filter((call) => call.url === "/api/audit/integrity").length, 1);
});

test("support unread count shows on the Support chat link", async (t) => {
  stubFetch(t, { unread: 3 });
  renderShell(admin, "/support");
  await waitFor(() => assert.ok(within(fullNav()).getByRole("link", { name: "Support chat 3 unread" })));
});

test("sign out posts to the logout route from the operator menu", async (t) => {
  const calls = stubFetch(t);
  const assign = t.mock.fn();
  t.mock.method(window.location, "assign", assign);
  renderShell();
  fireEvent.click(screen.getByRole("button", { name: /Account: a\.rivera@clinic\.example, / }));
  fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
  await waitFor(() => assert.ok(calls.some((call) => call.url === "/api/auth/logout" && call.method === "POST")));
});

test("global search submits to the device list with a bounded query", () => {
  const original = globalThis.fetch;
  globalThis.fetch = (async () => Response.json({ unread: 0 })) as typeof fetch;
  try {
    renderShell();
    const search = screen.getByRole("searchbox", { name: "Search devices" }) as HTMLInputElement;
    const form = search.closest("form")!;
    assert.equal(new URL(form.action).pathname, "/endpoints");
    assert.equal(form.method, "get");
    assert.equal(search.name, "search");
    assert.equal(search.maxLength, 100);
  } finally {
    globalThis.fetch = original;
  }
});

test("the assistant launcher appears only when the shell is given an assistant state", (t) => {
  stubFetch(t);
  const without = renderShell();
  assert.equal(screen.queryByRole("button", { name: "AI assistant" }), null);
  without.unmount();

  render(
    <AppShell activePath="/endpoints" navigation={{ items: [], truncated: false }} navigationError={false} operator={readonly} assistantState="disabled">
      <p>Page body</p>
    </AppShell>,
  );
  assert.equal(screen.getByRole("button", { name: "AI assistant" }).getAttribute("aria-expanded"), "false");
  assert.equal(within(fullNav()).queryByRole("link", { name: "AI assistant" }), null, "the sidebar entry is gone");
});
