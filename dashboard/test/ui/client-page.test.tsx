// SPDX-License-Identifier: AGPL-3.0-only
// The client details page (issue #311): call it with mocked loaders, then
// render whatever element it returns.
import assert from "node:assert/strict";
import { mock, test } from "node:test";
import { render, screen } from "@testing-library/react";

import type { DashboardSessionState } from "@/lib/dashboard-auth-core";
import { NodelinkApiError } from "@/lib/nodelink-api-core";

class NavigationSignal extends Error {}

let session: DashboardSessionState = { kind: "anonymous" };
let loadClient: () => Promise<unknown> = async () => ({ id: "client-1", name: "Acme Dental", sites: [] });
let loadPolicy: () => Promise<unknown> = async () => ({ clientId: "client-1" });

mock.module("@/lib/dashboard-session", { namedExports: { getDashboardSession: async () => session } });
mock.module("@/lib/nodelink-api", { namedExports: { NodelinkApiError } });
mock.module("@/lib/client-navigation", { namedExports: { getClientNavigationEntry: () => loadClient() } });
mock.module("@/lib/retention-policy", { namedExports: { getRetentionPolicy: () => loadPolicy() } });
mock.module("@/components/retention-policy-panel", {
  namedExports: {
    RetentionPolicyPanel: ({ clientId }: { clientId: string }) => <h2>Retention for {clientId}</h2>,
  },
});
mock.module("next/navigation", {
  namedExports: {
    notFound: () => { throw new NavigationSignal("not-found"); },
    redirect: (to: string) => { throw new NavigationSignal(`redirect:${to}`); },
  },
});

const { default: ClientPage } = await import("@/app/clients/[clientId]/page");

const signedIn = {
  kind: "authenticated",
  operator: { id: "op-1", email: "tech@example.com", role: "readonly" },
  sessionToken: "session-token",
} as DashboardSessionState;

function visit(clientId = "client-1") {
  return ClientPage({ params: Promise.resolve({ clientId }) });
}

test("an anonymous visitor is redirected to sign in", async () => {
  session = { kind: "anonymous" };
  await assert.rejects(visit(), { message: "redirect:/login" });
});

test("a client the operator cannot see is the not-found page, from either loader", async () => {
  session = signedIn;
  loadClient = async () => { throw new NodelinkApiError(404, "Not found"); };
  loadPolicy = async () => ({ clientId: "client-1" });
  await assert.rejects(visit(), { message: "not-found" });
  loadClient = async () => ({ id: "client-1", name: "Acme Dental", sites: [] });
  loadPolicy = async () => { throw new NodelinkApiError(404, "Not found"); };
  await assert.rejects(visit(), { message: "not-found" });
});

test("a visible client renders its name and retention section", async () => {
  session = signedIn;
  loadClient = async () => ({ id: "client-1", name: "Acme Dental", sites: [] });
  loadPolicy = async () => ({ clientId: "client-1" });
  render(await visit());
  assert.ok(screen.getByRole("heading", { name: "Acme Dental" }));
  assert.ok(screen.getByRole("heading", { name: "Retention for client-1" }));
});

test("an unavailable policy shows a retry state, not an empty editor", async () => {
  session = signedIn;
  loadPolicy = async () => { throw new NodelinkApiError(500, "down"); };
  render(await visit());
  assert.match(screen.getByRole("alert").textContent ?? "", /could not be loaded/);
  assert.equal(screen.queryByRole("heading", { name: /Retention for/ }), null);
});
