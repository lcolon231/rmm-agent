// SPDX-License-Identifier: AGPL-3.0-only
// The /community server page and layout, with loaders and session mocked.
import assert from "node:assert/strict";
import { mock, test } from "node:test";
import { render, screen } from "@testing-library/react";

import { loadAssistantContext } from "@/lib/assistant-context-core";
import type { DashboardSessionState } from "@/lib/dashboard-auth-core";

class NavigationSignal extends Error {}

let session: DashboardSessionState = { kind: "anonymous" };
let failLoad = false;
const listCommunityPublishers = mock.fn(async (token: string) => { assert.ok(token); if (failLoad) throw new Error("bad"); return []; });
const listCommunityPackages = mock.fn(async (token: string) => { assert.ok(token); return { items: [], total: 0 }; });
const listCommunityInstalls = mock.fn(async (token: string) => { assert.ok(token); return []; });
let viewProps: Record<string, unknown> = {};

mock.module("@/lib/dashboard-session", { namedExports: { getDashboardSession: async () => session } });
mock.module("@/lib/community-packages", {
  namedExports: { listCommunityPublishers, listCommunityPackages, listCommunityInstalls },
});
mock.module("@/lib/assistant-context", {
  namedExports: {
    getAssistantContext: () =>
      loadAssistantContext({ navigation: async () => { throw new Error("nav down"); }, status: async () => ({ state: "available" }) }),
  },
});
mock.module("@/components/community-repository-view", {
  namedExports: { CommunityRepositoryView: (props: Record<string, unknown>) => { viewProps = props; return <p>view:{String(props.initialError || "ok")}</p>; } },
});
mock.module("@/components/dashboard-shell", {
  namedExports: { DashboardSectionShell: ({ children, activePath, navigationError, assistantState }: { children: React.ReactNode; activePath: string; navigationError: boolean; assistantState?: string }) =>
    <section data-active={activePath} data-nav-error={String(navigationError)} data-assistant={assistantState}>{children}</section> },
});
mock.module("next/navigation", {
  namedExports: { redirect: (to: string) => { throw new NavigationSignal(`redirect:${to}`); } },
});

const { default: CommunityPage } = await import("@/app/community/page");
const { default: CommunityLayout } = await import("@/app/community/layout");

const signedIn = { kind: "authenticated", operator: { id: "op-1", email: "a@test", role: "admin" },
  sessionToken: "session-token" } as DashboardSessionState;

test("anonymous visitors are redirected from the page and the layout", async () => {
  session = { kind: "anonymous" };
  await assert.rejects(CommunityPage(), { message: "redirect:/login" });
  await assert.rejects(CommunityLayout({ children: null }), { message: "redirect:/login" });
});

test("an unverifiable session renders no repository data", async () => {
  session = { kind: "unavailable" };
  render(await CommunityLayout({ children: <p>secret children</p> }));
  assert.ok(screen.getByText("Community scripts are unavailable"));
  assert.equal(screen.queryByText("secret children"), null);
});

test("the layout keeps rendering when navigation cannot load", async () => {
  session = signedIn;
  const { container } = render(await CommunityLayout({ children: <p>body</p> }));
  const shell = container.querySelector("section");
  assert.equal(shell?.getAttribute("data-active"), "/community");
  assert.equal(shell?.getAttribute("data-nav-error"), "true");
  assert.equal(shell?.getAttribute("data-assistant"), "available", "the layout hands the assistant state to the shell");
});

test("loaded data is passed through with the operator's role", async () => {
  session = signedIn; failLoad = false;
  render(await CommunityPage());
  assert.ok(screen.getByText("view:ok"));
  assert.deepEqual(viewProps.packages, []);
  assert.equal(viewProps.role, "admin");
  assert.equal(listCommunityPublishers.mock.calls.at(-1)?.arguments[0], "session-token");
});

test("any load failure shows a fail-closed error and no records", async () => {
  session = signedIn; failLoad = true;
  render(await CommunityPage());
  assert.match(screen.getByText(/view:/).textContent ?? "", /could not be verified/);
  assert.equal(viewProps.publishers, null);
  assert.equal(viewProps.packages, null);
  assert.equal(viewProps.installs, null);
});
