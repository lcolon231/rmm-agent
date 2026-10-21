// SPDX-License-Identifier: AGPL-3.0-only

/** Command dispatch and remote desktop route cores (issue #280). */

import assert from "node:assert/strict";
import test from "node:test";

import { handleDispatchCommand } from "../src/lib/command-dispatch-route-core.ts";
import {
  handleLaunchRemoteDesktop,
  handleRemoteDesktopAvailability,
} from "../src/lib/remote-desktop-route-core.ts";
import { SENTINEL, apiError, bffContract, request, sessionFor, upstream } from "./bff-contract.ts";

const dispatchBody = { kind: "collect_inventory", script: "", ttl_seconds: 300 };
const launch = {
  id: "launch-1",
  agent_id: "agent-1",
  status: "authorized",
  login_url: "https://mesh.example.test/one-time",
  created_at: "2026-10-21T12:00:00Z",
  mesh_admin_cookie: SENTINEL,
};

bffContract([
  {
    name: "dispatch command",
    minRole: "readonly",
    mutation: true,
    upstreamResult: { id: "command-1", status: "pending", signature: SENTINEL },
    invoke: ({ getSession, origin, call }) =>
      handleDispatchCommand(
        request("/api/endpoints/agent-1/commands", "POST", dispatchBody, origin),
        "agent-1",
        { dispatchCommand: call, getSession },
      ),
  },
  {
    name: "remote desktop availability",
    minRole: "readonly",
    mutation: false,
    upstreamResult: { available: true, reason: "ready", provider_enabled: true, node_id: SENTINEL },
    invoke: ({ getSession, call }) =>
      handleRemoteDesktopAvailability(request("/api/endpoints/agent-1/remote-desktop/availability"), "agent-1", {
        getRemoteDesktopAvailability: call,
        getSession,
      }),
  },
  {
    name: "launch remote desktop",
    minRole: "operator",
    mutation: true,
    upstreamResult: launch,
    invoke: ({ getSession, origin, call }) =>
      handleLaunchRemoteDesktop(
        request("/api/endpoints/agent-1/remote-desktop/launches", "POST", undefined, origin),
        "agent-1",
        { getSession, launchRemoteDesktop: call },
      ),
  },
]);

function dispatch(body: unknown, dispatchCommand: (...args: unknown[]) => Promise<unknown>) {
  return handleDispatchCommand(request("/api/endpoints/agent-1/commands", "POST", body), "agent-1", {
    dispatchCommand,
    getSession: sessionFor("operator"),
  });
}

test("dispatch refuses malformed and invalid bodies before forwarding", async () => {
  for (const body of ["{not json", { kind: "erase_disk", script: "x", ttl_seconds: 300 }]) {
    const double = upstream({ id: "command-1", status: "pending" });
    const response = await dispatch(body, double.fn);
    assert.equal(response.status, 400);
    assert.equal(double.calls.length, 0);
  }
});

test("dispatch maps refusal codes to operator text and surfaces only navigable codes", async () => {
  const cases: Array<[number, string | null, number, RegExp, string | undefined]> = [
    [403, "script_execution_not_authorized", 403, /administrator-granted scope/, undefined],
    [401, null, 403, /not allowed to dispatch/, undefined],
    [404, null, 404, /no longer exists/, undefined],
    [422, null, 400, /rejected this typed operation/, undefined],
    [409, "agent_not_trusted", 409, /quarantined or revoked/, undefined],
    [409, "power_operation_maintenance_window_required", 409, /maintenance window/, "power_operation_maintenance_window_required"],
    [429, null, 429, /queue is full/, undefined],
    [500, "internal_detail", 502, /could not be dispatched/, undefined],
  ];
  for (const [upstreamStatus, code, status, message, surfacedCode] of cases) {
    const response = await dispatch(dispatchBody, async () => { throw apiError(upstreamStatus, code); });
    assert.equal(response.status, status);
    const body = await response.json();
    assert.match(body.error, message);
    assert.equal(body.code, surfacedCode);
  }
});

test("dispatch treats a non-API failure or bad upstream record as 502", async () => {
  const thrown = await dispatch(dispatchBody, async () => { throw new TypeError("fetch failed"); });
  assert.equal(thrown.status, 502);
  const malformed = await dispatch(dispatchBody, async () => ({ id: 7 }));
  assert.equal(malformed.status, 502);
});

test("remote desktop launch keeps the one-time login URL and maps refusals", async () => {
  const ok = await handleLaunchRemoteDesktop(request("/x", "POST"), "agent-1", {
    getSession: sessionFor("operator"),
    launchRemoteDesktop: async () => launch,
  });
  assert.equal(ok.status, 201);
  assert.equal((await ok.json()).launch.login_url, launch.login_url);

  for (const [upstreamStatus, status] of [[409, 409], [429, 429], [503, 503], [500, 403]]) {
    const response = await handleLaunchRemoteDesktop(request("/x", "POST"), "agent-1", {
      getSession: sessionFor("operator"),
      launchRemoteDesktop: async () => { throw apiError(upstreamStatus, "remote_desktop_disabled"); },
    });
    assert.equal(response.status, status);
  }
});

test("remote desktop availability hides upstream detail on failure", async () => {
  for (const [upstreamStatus, status] of [[404, 404], [401, 401], [500, 502]]) {
    const response = await handleRemoteDesktopAvailability(request("/x"), "agent-1", {
      getRemoteDesktopAvailability: async () => { throw apiError(upstreamStatus); },
      getSession: sessionFor("readonly"),
    });
    assert.equal(response.status, status);
    assert.deepEqual(await response.json(), { error: "Remote desktop availability is unavailable." });
  }
});
