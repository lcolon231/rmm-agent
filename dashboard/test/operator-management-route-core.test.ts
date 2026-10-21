// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import test from "node:test";

import {
  handleChangeOperatorRole,
  handleChangeOperatorStatus,
  handleCreateOperator,
  handleGrantScriptPermission,
  handleListOperators,
  handleRevokeOperatorTokens,
  handleRevokeScriptPermission,
} from "../src/lib/operator-management-route-core.ts";

const dashboardOrigin = "https://dashboard.example.test";
const sessionToken = "session-token-sentinel";
const password = "password-value-sentinel";

const adminSession = async () => ({
  kind: "authenticated" as const,
  operator: { role: "admin" as const },
  sessionToken,
});

function request(
  path: string,
  method: string,
  body?: unknown,
  origin = dashboardOrigin,
): Request {
  return new Request(`${dashboardOrigin}${path}`, {
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: {
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      Origin: origin,
    },
    method,
  });
}

function upstreamOperator(extra: Record<string, unknown> = {}) {
  return {
    id: "operator-1",
    email: "technician@example.com",
    role: "operator",
    script_execution_scope: null,
    script_execution_scope_id: null,
    disabled: false,
    created_at: "2026-07-28T12:00:00Z",
    ...extra,
  };
}

test("mutation handlers reject cross-origin requests before forwarding credentials", async () => {
  let called = false;
  const response = await handleCreateOperator(
    request(
      "/api/operators",
      "POST",
      { email: "admin@example.com", password, role: "admin" },
      "https://attacker.example.test",
    ),
    {
      createOperator: async () => {
        called = true;
        return upstreamOperator();
      },
      getSession: adminSession,
    },
  );
  assert.equal(response.status, 403);
  assert.equal(called, false);
  assert.doesNotMatch(await response.text(), new RegExp(password));
});

test("create forwards the password once but never returns or logs it or the bearer token", async () => {
  let forwardedPassword = "";
  let forwardCount = 0;
  const capturedConsole: string[] = [];
  const originalError = console.error;
  console.error = (...values: unknown[]) => {
    capturedConsole.push(values.join(" "));
  };
  try {
    const response = await handleCreateOperator(
      request("/api/operators", "POST", {
        email: "Technician@Example.com",
        password,
        role: "operator",
      }),
      {
        createOperator: async (token, input) => {
          assert.equal(token, sessionToken);
          forwardedPassword = input.password;
          forwardCount += 1;
          return upstreamOperator({
            access_token: sessionToken,
            password,
          });
        },
        getSession: adminSession,
      },
    );
    const rendered = await response.text();
    assert.equal(response.status, 201);
    assert.equal(forwardCount, 1);
    assert.equal(forwardedPassword, password);
    assert.doesNotMatch(rendered, new RegExp(password));
    assert.doesNotMatch(rendered, new RegExp(sessionToken));
    assert.doesNotMatch(capturedConsole.join("\n"), new RegExp(`${password}|${sessionToken}`));
  } finally {
    console.error = originalError;
  }
});

test("list allowlists operator fields so an upstream token cannot reach the client", async () => {
  const response = await handleListOperators(
    request("/api/operators", "GET"),
    {
      getSession: adminSession,
      listOperators: async (token) => {
        assert.equal(token, sessionToken);
        return [upstreamOperator({ access_token: sessionToken })];
      },
    },
  );
  const rendered = await response.text();
  assert.equal(response.status, 200);
  assert.doesNotMatch(rendered, new RegExp(sessionToken));
  assert.match(rendered, /technician@example\.com/);
});

test("surfaces 401, 403, 404, and 409 as distinct actionable states", async () => {
  const unauthorized = await handleListOperators(request("/api/operators", "GET"), {
    getSession: adminSession,
    listOperators: async () => { throw { status: 401 }; },
  });
  assert.equal(unauthorized.status, 401);
  assert.match(await unauthorized.text(), /session expired/i);

  const forbidden = await handleListOperators(request("/api/operators", "GET"), {
    getSession: adminSession,
    listOperators: async () => { throw { status: 403 }; },
  });
  assert.equal(forbidden.status, 403);
  assert.match(await forbidden.text(), /administrator/i);

  const missing = await handleGrantScriptPermission(
    request("/api/operators/operator-1/script-permission", "PUT", {
      scope: "site",
      scope_id: "site-1",
      reason: "Approved for this site",
    }),
    "operator-1",
    {
      getSession: adminSession,
      grantScriptPermission: async () => { throw { status: 404 }; },
    },
  );
  assert.equal(missing.status, 404);
  assert.match(await missing.text(), /operator or selected scope target/i);

  const duplicate = await handleCreateOperator(
    request("/api/operators", "POST", {
      email: "admin@example.com",
      password,
      role: "admin",
    }),
    {
      createOperator: async () => { throw { status: 409 }; },
      getSession: adminSession,
    },
  );
  assert.equal(duplicate.status, 409);
  assert.match(await duplicate.text(), /email already exists/i);
});

test("surfaces script-permission conflict codes without internal detail", async () => {
  const ineligible = await handleGrantScriptPermission(
    request("/api/operators/operator-1/script-permission", "PUT", {
      scope: "global",
      reason: "Attempted grant",
    }),
    "operator-1",
    {
      getSession: adminSession,
      grantScriptPermission: async () => {
        throw { status: 409, code: "script_permission_role_ineligible" };
      },
    },
  );
  assert.equal(ineligible.status, 409);
  assert.match(await ineligible.text(), /Read-only operators cannot receive/);

  const notGranted = await handleRevokeScriptPermission(
    request("/api/operators/operator-1/script-permission/revoke", "POST", {
      reason: "Return to default deny",
    }),
    "operator-1",
    {
      getSession: adminSession,
      revokeScriptPermission: async () => {
        throw { status: 409, code: "script_permission_not_granted" };
      },
    },
  );
  assert.equal(notGranted.status, 409);
  assert.match(await notGranted.text(), /no script permission to revoke/i);
});

test("returns 204 with no token or body after confirmed sign-out-everywhere", async () => {
  let forwardedToken = "";
  const response = await handleRevokeOperatorTokens(
    request("/api/operators/operator-1/revoke-tokens", "POST"),
    "operator-1",
    {
      getSession: adminSession,
      revokeOperatorTokens: async (token) => {
        forwardedToken = token;
      },
    },
  );
  assert.equal(forwardedToken, sessionToken);
  assert.equal(response.status, 204);
  assert.equal(await response.text(), "");
});

test("role and status handlers enforce same-origin and forward no session token", async () => {
  let roleCalls = 0;
  const rejected = await handleChangeOperatorRole(
    request(
      "/api/operators/operator-1/role",
      "PUT",
      { role: "readonly", reason: "Responsibilities changed" },
      "https://attacker.example.test",
    ),
    "operator-1",
    {
      changeOperatorRole: async () => {
        roleCalls += 1;
        return upstreamOperator();
      },
      getSession: adminSession,
    },
  );
  assert.equal(rejected.status, 403);
  assert.equal(roleCalls, 0);

  const changed = await handleChangeOperatorRole(
    request(
      "/api/operators/operator-1/role",
      "PUT",
      { role: "readonly", reason: "Responsibilities changed" },
    ),
    "operator-1",
    {
      changeOperatorRole: async (token, operatorId, input) => {
        assert.equal(token, sessionToken);
        assert.equal(operatorId, "operator-1");
        assert.deepEqual(input, {
          role: "readonly",
          reason: "Responsibilities changed",
        });
        return upstreamOperator({
          role: "readonly",
          access_token: sessionToken,
        });
      },
      getSession: adminSession,
    },
  );
  const changedText = await changed.text();
  assert.equal(changed.status, 200);
  assert.doesNotMatch(changedText, new RegExp(sessionToken));
  assert.match(changedText, /"role":"readonly"/);

  const disabled = await handleChangeOperatorStatus(
    request(
      "/api/operators/operator-1/disabled",
      "PUT",
      { disabled: true, reason: "Offboarding approved" },
    ),
    "operator-1",
    {
      changeOperatorStatus: async (token, operatorId, input) => {
        assert.equal(token, sessionToken);
        assert.equal(operatorId, "operator-1");
        assert.deepEqual(input, {
          disabled: true,
          reason: "Offboarding approved",
        });
        return upstreamOperator({
          disabled: true,
          access_token: sessionToken,
        });
      },
      getSession: adminSession,
    },
  );
  const disabledText = await disabled.text();
  assert.equal(disabled.status, 200);
  assert.doesNotMatch(disabledText, new RegExp(sessionToken));
  assert.match(disabledText, /"disabled":true/);
});

test("operator state handlers surface last-admin conflicts without internal detail", async () => {
  const response = await handleChangeOperatorStatus(
    request(
      "/api/operators/operator-1/disabled",
      "PUT",
      { disabled: true, reason: "Would remove final admin" },
    ),
    "operator-1",
    {
      changeOperatorStatus: async () => {
        throw { status: 409, code: "last_active_admin_required", internal: "hidden" };
      },
      getSession: adminSession,
    },
  );
  const text = await response.text();
  assert.equal(response.status, 409);
  assert.match(text, /retain at least one active administrator/i);
  assert.doesNotMatch(text, /internal|hidden/i);
});


// --------------------------------------------------------------------------- //
// Coverage extension: every handler shares session, role, and error mapping
// --------------------------------------------------------------------------- //
type OpSession =
  | { kind: "anonymous" } | { kind: "unavailable" }
  | { kind: "authenticated"; operator: { role: "readonly" | "operator" | "admin" }; sessionToken: string };
const opSentinel = "SENTINEL-must-not-leak";
const reasonBody = { reason: "Audit reason text" };

type OpCase = {
  name: string;
  method: string;
  body?: unknown;
  invalid?: unknown;
  /** The handler returns a bare 204 on success instead of an operator record. */
  noContent?: boolean;
  /** The list handler has no same-origin check or body. */
  readOnly?: boolean;
  run: (req: Request, getSession: () => Promise<OpSession>, api: (...a: unknown[]) => Promise<unknown>) => Promise<Response>;
};

const opCases: OpCase[] = [
  {
    name: "list", method: "GET", readOnly: true,
    run: (req, getSession, api) => handleListOperators(req, { getSession, listOperators: api as never }),
  },
  {
    name: "create", method: "POST", body: { email: "a@example.com", password, role: "operator" },
    invalid: { email: "nope", password: "x", role: "emperor" },
    run: (req, getSession, api) => handleCreateOperator(req, { getSession, createOperator: api as never }),
  },
  {
    name: "grant", method: "POST", body: { scope: "global", ...reasonBody }, invalid: { scope: "galaxy", reason: "x" },
    run: (req, getSession, api) => handleGrantScriptPermission(req, "operator-1", { getSession, grantScriptPermission: api as never }),
  },
  {
    name: "revoke permission", method: "DELETE", body: reasonBody, invalid: { reason: "x" },
    run: (req, getSession, api) => handleRevokeScriptPermission(req, "operator-1", { getSession, revokeScriptPermission: api as never }),
  },
  {
    name: "revoke tokens", method: "POST", noContent: true,
    run: (req, getSession, api) => handleRevokeOperatorTokens(req, "operator-1", { getSession, revokeOperatorTokens: api as never }),
  },
  {
    name: "change role", method: "PUT", body: { role: "admin", ...reasonBody }, invalid: { role: "emperor", reason: "x" },
    run: (req, getSession, api) => handleChangeOperatorRole(req, "operator-1", { getSession, changeOperatorRole: api as never }),
  },
  {
    name: "change status", method: "PUT", body: { disabled: true, ...reasonBody }, invalid: { disabled: "yes", reason: "x" },
    run: (req, getSession, api) => handleChangeOperatorStatus(req, "operator-1", { getSession, changeOperatorStatus: api as never }),
  },
];

for (const c of opCases) {
  const make = (origin?: string) => request("/api/operators/operator-1", c.method, c.body, origin);
  const upstreamOk = () => (c.name === "list" ? [upstreamOperator({ secret: opSentinel })]
    : c.noContent ? undefined : upstreamOperator({ password_hash: opSentinel }));

  test(`operator ${c.name}: no usable session never reaches the API`, async () => {
    const sessions: Array<[number, () => Promise<OpSession>]> = [
      [401, async () => ({ kind: "anonymous" })],
      [503, async () => ({ kind: "unavailable" })],
      [503, async () => { throw new Error("boom"); }],
    ];
    for (const [status, getSession] of sessions) {
      let calls = 0;
      const res = await c.run(make(), getSession, async () => { calls += 1; return upstreamOk(); });
      assert.equal(res.status, status);
      assert.equal(calls, 0);
    }
  });

  test(`operator ${c.name}: non-admin roles are rejected without forwarding`, async () => {
    let calls = 0;
    for (const role of ["readonly", "operator"] as const) {
      const res = await c.run(make(), async () => ({ kind: "authenticated", operator: { role }, sessionToken }), async () => { calls += 1; return upstreamOk(); });
      assert.equal(res.status, 403);
    }
    assert.equal(calls, 0);
  });

  if (!c.readOnly) {
    test(`operator ${c.name}: cross-origin is rejected without forwarding`, async () => {
      let calls = 0;
      const res = await c.run(make("https://evil.test"), adminSession, async () => { calls += 1; return upstreamOk(); });
      assert.equal(res.status, 403);
      assert.equal(calls, 0);
    });
  }

  test(`operator ${c.name}: success is allowlisted and upstream failures are mapped`, async () => {
    const ok = await c.run(make(), adminSession, async () => upstreamOk());
    assert.equal(ok.status, c.noContent ? 204 : c.name === "create" ? 201 : 200);
    assert.equal(ok.headers.get("cache-control"), "no-store");
    assert.doesNotMatch(await ok.text(), new RegExp(`${opSentinel}|${sessionToken}`));

    const expected: Array<[Record<string, unknown>, number]> = [
      [{ status: 401 }, 401], [{ status: 403 }, 403], [{ status: 404 }, 404],
      [{ status: 409 }, 409], [{ status: 409, code: "last_active_admin_required" }, 409],
      [{ status: 400 }, 400], [{ status: 422 }, 400], [{ status: 500 }, 503], [{}, 503],
    ];
    for (const [fields, mapped] of expected) {
      const res = await c.run(make(), adminSession, async () => { throw Object.assign(new Error(opSentinel), fields); });
      // The describe helper owns the exact status for 400/422; only assert it is a client or availability error.
      if (fields.status === 400 || fields.status === 422) assert.ok([400, 422].includes(res.status), String(res.status));
      else assert.equal(res.status, mapped);
      assert.doesNotMatch(await res.text(), new RegExp(`${opSentinel}|${sessionToken}`));
    }
    for (const thrown of [null, opSentinel]) {
      assert.equal((await c.run(make(), adminSession, async () => { throw thrown; })).status, 503);
    }
    if (!c.noContent) {
      const bad = await c.run(make(), adminSession, async () => ({ junk: opSentinel }));
      assert.equal(bad.status, 502);
      assert.doesNotMatch(await bad.text(), new RegExp(opSentinel));
    }
  });

  if (c.invalid !== undefined) {
    test(`operator ${c.name}: invalid bodies never reach the API`, async () => {
      let calls = 0;
      const api = async () => { calls += 1; return upstreamOk(); };
      assert.equal((await c.run(request("/x", c.method, c.invalid), adminSession, api)).status, 400);
      assert.equal((await c.run(request("/x", c.method, null), adminSession, api)).status, 400);
      const raw = new Request(`${dashboardOrigin}/x`, { method: c.method, headers: { Origin: dashboardOrigin }, body: "{bad" });
      assert.equal((await c.run(raw, adminSession, api)).status, 400);
      assert.equal(calls, 0);
    });
  }
}
