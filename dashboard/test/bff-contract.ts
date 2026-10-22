// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The BFF contract every proxied route core must honour (issue #280).
 *
 * Not a test file itself: each `*-route-core.test.ts` hands its handlers to
 * `bffContract`, which generates the same refusal and allowlisting tests for
 * every one, so a new handler cannot quietly skip a check.
 */

import assert from "node:assert/strict";
import test from "node:test";

import type { GetSession, RouteRole, RouteSession } from "../src/lib/bff-route-core.ts";

export const dashboardOrigin = "https://dashboard.example.test";
export const sessionToken = "session-token-sentinel";
/** Planted in every upstream record; must never reach a response body. */
export const SENTINEL = "upstream-sentinel-must-not-leak";

export function sessionFor(role: RouteRole): GetSession {
  return async () => ({ kind: "authenticated", operator: { role }, sessionToken });
}

export const revokedSession: GetSession = async () => ({ kind: "anonymous" });
export const unavailableSession: GetSession = async () => ({ kind: "unavailable" });
export const throwingSession: GetSession = async (): Promise<RouteSession> => {
  throw new Error("auth/me exploded");
};

export function request(
  path: string,
  method = "GET",
  body?: unknown,
  origin: string | null = dashboardOrigin,
): Request {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (origin !== null) headers.Origin = origin;
  return new Request(`${dashboardOrigin}${path}`, {
    body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
    headers,
    method,
  });
}

/** An upstream double that records each call and answers with `result`. */
export function upstream<T = unknown>(result: T | (() => T | Promise<T>)) {
  const calls: unknown[][] = [];
  const fn = async (...args: unknown[]) => {
    calls.push(args);
    return typeof result === "function" ? (result as () => T | Promise<T>)() : result;
  };
  return { calls, fn };
}

/** A thrown `NodelinkApiError` lookalike; cores read it by shape. */
export function apiError(status: number, code: string | null = null) {
  return Object.assign(new Error("NodeLink API request failed."), { status, code });
}

export type ContractCase = {
  name: string;
  minRole: RouteRole;
  /** Mutations must refuse a foreign Origin before anything else. */
  mutation: boolean;
  /** A valid upstream answer carrying {@link SENTINEL} in an unknown field;
   * a function is called per request (for single-use bodies such as a Response). */
  upstreamResult: unknown;
  invoke: (input: {
    getSession: GetSession;
    origin: string;
    call: (...args: unknown[]) => Promise<unknown>;
  }) => Promise<Response>;
};

const roles: RouteRole[] = ["readonly", "operator", "admin"];
const rank: Record<RouteRole, number> = { readonly: 0, operator: 1, admin: 2 };

export function bffContract(cases: ContractCase[]): void {
  for (const spec of cases) {
    const run = (getSession: GetSession, origin = dashboardOrigin) => {
      const double = upstream(spec.upstreamResult);
      return spec.invoke({ getSession, origin, call: double.fn }).then((response) => ({
        calls: double.calls,
        response,
      }));
    };

    test(`${spec.name}: a revoked session is refused with 401 before forwarding`, async () => {
      const { calls, response } = await run(revokedSession);
      assert.equal(response.status, 401);
      assert.equal(calls.length, 0);
    });

    test(`${spec.name}: unverifiable sessions are refused with 503 before forwarding`, async () => {
      for (const getSession of [unavailableSession, throwingSession]) {
        const { calls, response } = await run(getSession);
        assert.equal(response.status, 503);
        assert.equal(calls.length, 0);
      }
    });

    test(`${spec.name}: role floor is ${spec.minRole}`, async () => {
      for (const role of roles) {
        const { calls, response } = await run(sessionFor(role));
        if (rank[role] < rank[spec.minRole]) {
          assert.equal(response.status, 403, `${role} should be refused`);
          assert.equal(calls.length, 0, `${role} must not be forwarded`);
        } else {
          assert.equal(calls.length, 1, `${role} should be forwarded`);
          assert.equal(calls[0][0], sessionToken);
        }
      }
    });

    if (spec.mutation) {
      test(`${spec.name}: a cross-origin request is refused before the session is read`, async () => {
        let sessionRead = false;
        const getSession: GetSession = async () => {
          sessionRead = true;
          return sessionFor("admin")();
        };
        const { calls, response } = await run(getSession, "https://attacker.example.test");
        assert.equal(response.status, 403);
        assert.equal(calls.length, 0);
        assert.equal(sessionRead, false);
      });
    }

    test(`${spec.name}: unknown upstream fields are dropped`, async () => {
      const { response } = await run(sessionFor("admin"));
      assert.ok(response.status < 300, `expected success, got ${response.status}`);
      assert.equal(response.headers.get("cache-control"), "no-store");
      assert.ok(!(await response.text()).includes(SENTINEL));
    });
  }
}
