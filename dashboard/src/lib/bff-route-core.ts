// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Shared guards for the dashboard's BFF route cores (issue #280).
 *
 * Every proxied handler does the same three things before it forwards an
 * operator's server-held token: refuse cross-origin mutations, revalidate the
 * session against `/auth/me` (via the injected `getSession`, which in
 * production is `getDashboardSession`), and enforce a role floor that mirrors
 * the management service. Keeping them here means a core cannot forget one
 * step, and the tests can drive every branch without a Next runtime.
 */

import { isSameOrigin, requestOrigin } from "./dashboard-auth-core.ts";

export type RouteRole = "readonly" | "operator" | "admin";

export type RouteSession =
  | { kind: "anonymous" }
  | { kind: "unavailable" }
  | { kind: "authenticated"; operator: { role: RouteRole }; sessionToken: string };

export type GetSession = () => Promise<RouteSession>;

export type AuthorizedSession = { sessionToken: string; role: RouteRole };

const roleRank: Record<RouteRole, number> = { readonly: 0, operator: 1, admin: 2 };

export const SESSION_UNAVAILABLE_MESSAGE = "Operator session verification is unavailable.";

export function json(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

export function isSameOriginRequest(request: Request): boolean {
  return isSameOrigin(
    request.headers.get("origin"),
    requestOrigin(request.url, request.headers.get("host")),
  );
}

/**
 * Revalidate the session and apply a role floor.
 *
 * A revoked or expired token is reported as 401 and an unreachable `/auth/me`
 * as 503, in both cases before the caller touches the upstream API. A role
 * below `minRole` is a 403. Returns the token on success.
 */
export async function authorizeSession(
  getSession: GetSession,
  options: { minRole: RouteRole; signedOut: string; forbidden: string },
): Promise<AuthorizedSession | Response> {
  let session: RouteSession;
  try {
    session = await getSession();
  } catch {
    return json({ error: SESSION_UNAVAILABLE_MESSAGE }, 503);
  }
  if (session.kind === "anonymous") return json({ error: options.signedOut }, 401);
  if (session.kind === "unavailable") return json({ error: SESSION_UNAVAILABLE_MESSAGE }, 503);
  if (roleRank[session.operator.role] < roleRank[options.minRole]) {
    return json({ error: options.forbidden }, 403);
  }
  return { sessionToken: session.sessionToken, role: session.operator.role };
}

/** Read the `{status, code}` a `NodelinkApiError` carries, by shape, so cores
 * need not import the server-only API module. */
export function upstreamError(error: unknown): { status: number; code: string | null } | null {
  if (!error || typeof error !== "object") return null;
  const record = error as Record<string, unknown>;
  if (typeof record.status !== "number") return null;
  return { status: record.status, code: typeof record.code === "string" ? record.code : null };
}

/** Parse a JSON body, distinguishing "absent or malformed" (undefined). */
export async function readJsonBody(request: Request): Promise<unknown | undefined> {
  try {
    return await request.json();
  } catch {
    return undefined;
  }
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
