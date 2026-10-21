// SPDX-License-Identifier: AGPL-3.0-only
// Server pages are async functions: call them with mocked data loaders, then
// render whatever element they return.
import assert from "node:assert/strict";
import { mock, test } from "node:test";
import { render, screen } from "@testing-library/react";

import type { DashboardSessionState } from "@/lib/dashboard-auth-core";
import { NodelinkApiError } from "@/lib/nodelink-api-core";

class NavigationSignal extends Error {}

let session: DashboardSessionState = { kind: "anonymous" };
let loadDetail: () => Promise<unknown> = async () => null;
const getEndpointDetail = mock.fn(() => loadDetail());

mock.module("@/lib/dashboard-session", { namedExports: { getDashboardSession: async () => session } });
mock.module("@/lib/endpoint-detail", { namedExports: { getEndpointDetail } });
mock.module("@/lib/nodelink-api", { namedExports: { NodelinkApiError } });
mock.module("@/components/endpoint-detail-view", {
  namedExports: { EndpointDetailView: ({ endpoint }: { endpoint: { hostname: string } }) => <h1>Detail for {endpoint.hostname}</h1> },
});
mock.module("next/navigation", {
  namedExports: {
    notFound: () => { throw new NavigationSignal("not-found"); },
    redirect: (to: string) => { throw new NavigationSignal(`redirect:${to}`); },
  },
});

const { default: EndpointPage } = await import("@/app/endpoints/[endpointId]/page");

const operator = { id: "op-1", email: "tech@example.com", role: "technician" };
const signedIn: DashboardSessionState = { kind: "authenticated", operator, sessionToken: "session-token" } as DashboardSessionState;

function visit(endpointId: string, hours?: string) {
  return EndpointPage({ params: Promise.resolve({ endpointId }), searchParams: Promise.resolve({ hours }) });
}

test("an anonymous visitor is redirected to sign in", async () => {
  session = { kind: "anonymous" };
  await assert.rejects(visit("agent-1"), { message: "redirect:/login" });
});

test("an unverifiable session exposes no endpoint data", async () => {
  session = { kind: "unavailable" };
  getEndpointDetail.mock.resetCalls();
  render(await visit("agent-1"));
  assert.match(screen.getByRole("alert").textContent ?? "", /Endpoint details are temporarily unavailable/);
  assert.equal(getEndpointDetail.mock.callCount(), 0);
});

test("a 404 from the API becomes the not-found page", async () => {
  session = signedIn;
  loadDetail = async () => { throw new NodelinkApiError(404, "Not found"); };
  await assert.rejects(visit("agent-1"), { message: "not-found" });
});

for (const status of [403, 500]) {
  test(`a ${status} from the API renders the retry state, not a not-found or a blank detail`, async () => {
    session = signedIn;
    loadDetail = async () => { throw new NodelinkApiError(status, "refused"); };
    render(await visit("agent/1", "72"));
    assert.match(screen.getByRole("alert").textContent ?? "", /Telemetry could not be loaded/);
    assert.equal(screen.getByRole("link", { name: "Try again" }).getAttribute("href"), "/endpoints/agent%2F1?hours=72");
    assert.equal(screen.queryByRole("heading", { name: /Detail for/ }), null);
  });
}

test("an out-of-range history window falls back to 24 hours", async () => {
  session = signedIn;
  loadDetail = async () => ({ hostname: "WS-042" });
  getEndpointDetail.mock.resetCalls();
  render(await visit("agent-1", "9999"));
  assert.ok(screen.getByRole("heading", { name: "Detail for WS-042" }));
  assert.deepEqual(getEndpointDetail.mock.calls[0].arguments, ["session-token", "agent-1", { historyHours: 24, historyLimit: 500 }]);
});
