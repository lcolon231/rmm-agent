// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import test from "node:test";

import {
  handleMaintenanceWindowCreate,
  handleMaintenanceWindowDelete,
} from "../src/lib/maintenance-window-route-core.ts";

const NOW = Date.parse("2026-08-12T21:00:00Z");

const created = {
  id: "window-1",
  name: "Reboot for KB5120708",
  scope: "agent",
  scope_id: "agent-1",
  starts_at: "2026-08-12T20:55:00Z",
  ends_at: "2026-08-12T22:00:00Z",
  timezone: "UTC",
  recurrence: null,
  created_by: "admin@example.test",
  created_at: "2026-08-12T20:55:00Z",
};

const validBody = {
  name: "Reboot for KB5120708",
  scope: "agent",
  scope_id: "agent-1",
  starts_at: "2026-08-12T20:55:00.000Z",
  ends_at: "2026-08-12T22:00:00.000Z",
  timezone: "UTC",
};

function request(
  path: string,
  body: unknown,
  { origin = "https://dashboard.test", method = "POST" } = {},
) {
  return new Request(`https://dashboard.test${path}`, {
    method,
    headers: { "Content-Type": "application/json", Origin: origin },
    body: JSON.stringify(body),
  });
}

function session(role: "readonly" | "operator" | "admin") {
  return async () => ({
    kind: "authenticated" as const,
    operator: { role },
    sessionToken: "server-secret",
  });
}

const noopCreate = async () => created;

test("window creation refuses cross-origin requests and readonly operators", async () => {
  const dependencies = { getSession: session("readonly"), createWindow: noopCreate, now: () => NOW };
  assert.equal(
    (await handleMaintenanceWindowCreate(
      request("/api/maintenance-windows", validBody, { origin: "https://evil.test" }),
      { ...dependencies, getSession: session("admin") },
    )).status,
    403,
  );
  const refused = await handleMaintenanceWindowCreate(
    request("/api/maintenance-windows", validBody), dependencies,
  );
  assert.equal(refused.status, 403);
  assert.match((await refused.json()).error, /role cannot manage maintenance windows/);
});

test("window creation requires a verified session", async () => {
  const anonymous = await handleMaintenanceWindowCreate(
    request("/api/maintenance-windows", validBody),
    { getSession: async () => ({ kind: "anonymous" as const }), createWindow: noopCreate, now: () => NOW },
  );
  assert.equal(anonymous.status, 401);
  const unavailable = await handleMaintenanceWindowCreate(
    request("/api/maintenance-windows", validBody),
    { getSession: async () => { throw new Error("down"); }, createWindow: noopCreate, now: () => NOW },
  );
  assert.equal(unavailable.status, 503);
});

test("window creation forwards only re-validated input", async () => {
  let token = "";
  let forwarded: unknown;
  const response = await handleMaintenanceWindowCreate(
    request("/api/maintenance-windows", {
      ...validBody,
      name: "  Reboot for KB5120708  ",
      starts_at: "2026-08-12T16:55:00-04:00",
    }),
    {
      getSession: session("operator"),
      createWindow: async (receivedToken, input) => {
        token = receivedToken;
        forwarded = input;
        return created;
      },
      now: () => NOW,
    },
  );
  assert.equal(response.status, 201);
  assert.equal(token, "server-secret");
  assert.deepEqual(forwarded, {
    name: "Reboot for KB5120708",
    scope: "agent",
    scope_id: "agent-1",
    starts_at: "2026-08-12T20:55:00.000Z",
    ends_at: "2026-08-12T22:00:00.000Z",
    timezone: "UTC",
  });
  assert.deepEqual((await response.json()).window.id, "window-1");
});

test("window creation rejects invalid spans and scopes before any call is made", async () => {
  let called = false;
  const dependencies = {
    getSession: session("operator"),
    createWindow: async () => { called = true; return created; },
    now: () => NOW,
  };
  const invalid = [
    { ...validBody, ends_at: "2026-08-12T20:00:00.000Z" },
    { ...validBody, scope: "agent", scope_id: null },
    { ...validBody, scope: "global", scope_id: "agent-1" },
    { ...validBody, timezone: "Mars/Olympus" },
    { ...validBody, recurrence: { days: [1], start: "02:00", duration_minutes: 60 } },
    "not an object",
  ];
  for (const body of invalid) {
    const response = await handleMaintenanceWindowCreate(
      request("/api/maintenance-windows", body), dependencies,
    );
    assert.equal(response.status, 400, `expected ${JSON.stringify(body)} to be refused`);
  }
  assert.equal(called, false, "no invalid request reaches the management service");
});

test("service failures map to operator-readable outcomes", async () => {
  const failing = (status: number, code?: string) => ({
    getSession: session("operator"),
    createWindow: async () => { throw Object.assign(new Error("boom"), { status, code }); },
    now: () => NOW,
  });
  const cases: Array<[number, string | undefined, number, RegExp]> = [
    [403, undefined, 403, /role cannot manage/],
    [404, "monitoring_scope_target_not_found", 404, /client, site, or endpoint no longer exists/],
    [409, "maintenance_window_limit_reached", 409, /limit is reached/],
    [500, undefined, 503, /could not be confirmed/],
  ];
  for (const [status, code, expectedStatus, expectedMessage] of cases) {
    const response = await handleMaintenanceWindowCreate(
      request("/api/maintenance-windows", validBody), failing(status, code),
    );
    assert.equal(response.status, expectedStatus);
    assert.match((await response.json()).error, expectedMessage);
  }
});

test("a malformed service response is never presented as a created window", async () => {
  const response = await handleMaintenanceWindowCreate(
    request("/api/maintenance-windows", validBody),
    {
      getSession: session("operator"),
      createWindow: async () => ({ id: "window-1", name: "Broken" }),
      now: () => NOW,
    },
  );
  assert.equal(response.status, 502);
});

test("ending a window requires the typed name to match the live record", async () => {
  let deleted: string | null = null;
  const dependencies = {
    getSession: session("operator"),
    listWindows: async () => [{ id: "window-1", name: "Reboot for KB5120708" }],
    deleteWindow: async (_token: string, id: string) => { deleted = id; return null; },
  };

  const missing = await handleMaintenanceWindowDelete(
    request("/api/maintenance-windows/window-1", {}, { method: "DELETE" }), "window-1", dependencies,
  );
  assert.equal(missing.status, 400);
  assert.match((await missing.json()).error, /Type the window name/);

  const mismatched = await handleMaintenanceWindowDelete(
    request("/api/maintenance-windows/window-1", { confirm_name: "Wrong" }, { method: "DELETE" }),
    "window-1",
    dependencies,
  );
  assert.equal(mismatched.status, 409);

  const unknown = await handleMaintenanceWindowDelete(
    request("/api/maintenance-windows/window-9", { confirm_name: "Reboot for KB5120708" }, { method: "DELETE" }),
    "window-9",
    dependencies,
  );
  assert.equal(unknown.status, 404);
  assert.equal(deleted, null, "no delete is attempted until the confirmation matches");

  const confirmed = await handleMaintenanceWindowDelete(
    request("/api/maintenance-windows/window-1", { confirm_name: " Reboot for KB5120708 " }, { method: "DELETE" }),
    "window-1",
    dependencies,
  );
  assert.equal(confirmed.status, 200);
  assert.equal(deleted, "window-1");
});

test("ending a window enforces the same origin and role floor as creation", async () => {
  const dependencies = {
    getSession: session("readonly"),
    listWindows: async () => [{ id: "window-1", name: "Reboot for KB5120708" }],
    deleteWindow: async () => null,
  };
  const readonly = await handleMaintenanceWindowDelete(
    request("/api/maintenance-windows/window-1", { confirm_name: "Reboot for KB5120708" }, { method: "DELETE" }),
    "window-1",
    dependencies,
  );
  assert.equal(readonly.status, 403);

  const crossOrigin = await handleMaintenanceWindowDelete(
    request(
      "/api/maintenance-windows/window-1",
      { confirm_name: "Reboot for KB5120708" },
      { method: "DELETE", origin: "https://evil.test" },
    ),
    "window-1",
    { ...dependencies, getSession: session("admin") },
  );
  assert.equal(crossOrigin.status, 403);
});
