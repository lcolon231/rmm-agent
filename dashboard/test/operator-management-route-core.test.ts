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
