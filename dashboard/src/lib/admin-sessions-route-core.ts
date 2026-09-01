// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Route handlers for the session and break-glass proxy endpoints (issue #69).
 *
 * Dependencies are injected so every handler is testable without a running
 * server, matching `operator-management-route-core.ts` and `mfa-route-core.ts`.
 *
 * The invariants are the same as elsewhere in this layer: the session token
 * never reaches the browser, and every mutating request is same-origin checked
 * before a credential is attached to an upstream call.
 *
 * One endpoint breaks the pattern deliberately. Break-glass *activation* is
 * reachable without a session, because it is the escape hatch for the case
 * where no session can be obtained. It still gets the origin check -- a
 * cross-site page must not be able to spend a credential a user pastes -- and
 * the upstream applies the real rate limit.
 */

import { isSameOrigin, requestOrigin, sessionCookieName, sessionCookieOptions } from "./dashboard-auth-core.ts";
import {
  adminSessionErrorCode,
  adminSessionErrorMessage,
  validateCredential,
  validateLabel,
  validateReason,
  type AdminSessionErrorCode,
} from "./admin-sessions-core.ts";

type RouteSession =
  | { kind: "anonymous" }
  | { kind: "unavailable" }
  | { kind: "authenticated"; operator: { role: string }; sessionToken: string };

export type UpstreamResult = {
  status: number;
  code?: string | null;
  body?: unknown;
};

export type AdminSessionDependencies = {
  getSession: () => Promise<RouteSession>;
};

type CookieInstruction = {
  name: string;
  value: string;
  options: Record<string, unknown>;
};

export type AdminSessionRouteResult = {
  response: Response;
  cookies: CookieInstruction[];
};

function json(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

function fail(code: AdminSessionErrorCode, status: number): AdminSessionRouteResult {
  return { response: json({ error: adminSessionErrorMessage(code), code }, status), cookies: [] };
}

function sameOrigin(request: Request): boolean {
  return isSameOrigin(
    request.headers.get("origin"),
    requestOrigin(request.url, request.headers.get("host")),
  );
}

async function readBody(request: Request): Promise<unknown | undefined> {
  try {
    return await request.json();
  } catch {
    return undefined;
  }
}

function field(body: unknown, name: string): unknown {
  return body && typeof body === "object"
    ? (body as Record<string, unknown>)[name]
    : undefined;
}

async function requireToken(
  dependencies: AdminSessionDependencies,
): Promise<string | AdminSessionRouteResult> {
  let session: RouteSession;
  try {
    session = await dependencies.getSession();
  } catch {
    return fail("unavailable", 503);
  }
  if (session.kind === "unavailable") return fail("unavailable", 503);
  if (session.kind !== "authenticated") return fail("request-rejected", 401);
  return session.sessionToken;
}

function upstreamFailure(result: UpstreamResult): AdminSessionRouteResult {
  const code = adminSessionErrorCode(result.status, result.code);
  const status =
    result.status === 400
    || result.status === 401
    || result.status === 403
    || result.status === 404
    || result.status === 409
    || result.status === 429
      ? result.status
      : 503;
  return fail(code, status);
}

// --------------------------------------------------------------------------- //
// Sessions
// --------------------------------------------------------------------------- //
export async function handleListSessions(
  _request: Request,
  dependencies: AdminSessionDependencies & { list: (token: string) => Promise<UpstreamResult> },
): Promise<AdminSessionRouteResult> {
  const token = await requireToken(dependencies);
  if (typeof token !== "string") return token;
  const upstream = await dependencies.list(token);
  if (upstream.status !== 200) return upstreamFailure(upstream);
  return { response: json(upstream.body), cookies: [] };
}

export async function handleRevokeSession(
  request: Request,
  sessionId: string,
  dependencies: AdminSessionDependencies & {
    revoke: (token: string, id: string, body: unknown) => Promise<UpstreamResult>;
  },
): Promise<AdminSessionRouteResult> {
  if (!sameOrigin(request)) return fail("request-rejected", 403);
  const token = await requireToken(dependencies);
  if (typeof token !== "string") return token;

  const reason = validateReason(field(await readBody(request), "reason"));
  if (reason === null) return fail("invalid-request", 400);

  const upstream = await dependencies.revoke(token, sessionId, { reason });
  if (upstream.status !== 200) return upstreamFailure(upstream);
  return { response: json(upstream.body), cookies: [] };
}

export async function handleRevokeOtherSessions(
  request: Request,
  dependencies: AdminSessionDependencies & {
    revokeOthers: (token: string, body: unknown) => Promise<UpstreamResult>;
  },
): Promise<AdminSessionRouteResult> {
  if (!sameOrigin(request)) return fail("request-rejected", 403);
  const token = await requireToken(dependencies);
  if (typeof token !== "string") return token;

  const reason = validateReason(field(await readBody(request), "reason"));
  if (reason === null) return fail("invalid-request", 400);

  const upstream = await dependencies.revokeOthers(token, { reason });
  if (upstream.status !== 200) return upstreamFailure(upstream);
  return { response: json(upstream.body), cookies: [] };
}

// --------------------------------------------------------------------------- //
// Break-glass administration
// --------------------------------------------------------------------------- //
export async function handleListBreakGlass(
  _request: Request,
  dependencies: AdminSessionDependencies & { list: (token: string) => Promise<UpstreamResult> },
): Promise<AdminSessionRouteResult> {
  const token = await requireToken(dependencies);
  if (typeof token !== "string") return token;
  const upstream = await dependencies.list(token);
  if (upstream.status !== 200) return upstreamFailure(upstream);
  return { response: json(upstream.body), cookies: [] };
}

/**
 * Provision an emergency credential.
 *
 * The upstream body carries the plaintext credential exactly once. It is passed
 * straight through with `Cache-Control: no-store` and is never logged or
 * persisted anywhere in this layer.
 */
export async function handleCreateBreakGlass(
  request: Request,
  dependencies: AdminSessionDependencies & {
    create: (token: string, body: unknown) => Promise<UpstreamResult>;
  },
): Promise<AdminSessionRouteResult> {
  if (!sameOrigin(request)) return fail("request-rejected", 403);
  const token = await requireToken(dependencies);
  if (typeof token !== "string") return token;

  const body = await readBody(request);
  const label = validateLabel(field(body, "label"));
  const reason = validateReason(field(body, "reason"));
  if (label === null || reason === null) return fail("invalid-request", 400);

  const upstream = await dependencies.create(token, { label, reason });
  if (upstream.status !== 201) return upstreamFailure(upstream);
  return { response: json(upstream.body, 201), cookies: [] };
}

export async function handleRotateBreakGlass(
  request: Request,
  accountId: string,
  dependencies: AdminSessionDependencies & {
    rotate: (token: string, id: string, body: unknown) => Promise<UpstreamResult>;
  },
): Promise<AdminSessionRouteResult> {
  if (!sameOrigin(request)) return fail("request-rejected", 403);
  const token = await requireToken(dependencies);
  if (typeof token !== "string") return token;

  const reason = validateReason(field(await readBody(request), "reason"));
  if (reason === null) return fail("invalid-request", 400);

  const upstream = await dependencies.rotate(token, accountId, { reason });
  if (upstream.status !== 200) return upstreamFailure(upstream);
  return { response: json(upstream.body), cookies: [] };
}

export async function handleSetBreakGlassDisabled(
  request: Request,
  accountId: string,
  dependencies: AdminSessionDependencies & {
    setDisabled: (token: string, id: string, body: unknown) => Promise<UpstreamResult>;
  },
): Promise<AdminSessionRouteResult> {
  if (!sameOrigin(request)) return fail("request-rejected", 403);
  const token = await requireToken(dependencies);
  if (typeof token !== "string") return token;

  const body = await readBody(request);
  const reason = validateReason(field(body, "reason"));
  const disabled = field(body, "disabled");
  if (reason === null || typeof disabled !== "boolean") {
    return fail("invalid-request", 400);
  }

  const upstream = await dependencies.setDisabled(token, accountId, { disabled, reason });
  if (upstream.status !== 200) return upstreamFailure(upstream);
  return { response: json(upstream.body), cookies: [] };
}

export async function handleReviewActivation(
  request: Request,
  activationId: string,
  dependencies: AdminSessionDependencies & {
    review: (token: string, id: string, body: unknown) => Promise<UpstreamResult>;
  },
): Promise<AdminSessionRouteResult> {
  if (!sameOrigin(request)) return fail("request-rejected", 403);
  const token = await requireToken(dependencies);
  if (typeof token !== "string") return token;

  const note = validateReason(field(await readBody(request), "note"));
  if (note === null) return fail("invalid-request", 400);

  const upstream = await dependencies.review(token, activationId, { note });
  if (upstream.status !== 200) return upstreamFailure(upstream);
  return { response: json(upstream.body), cookies: [] };
}

// --------------------------------------------------------------------------- //
// Break-glass activation (no session required)
// --------------------------------------------------------------------------- //
/**
 * Exchange an emergency credential for a session cookie.
 *
 * Reachable without a session on purpose. The origin check stays -- a
 * cross-site page must not be able to spend a credential the user pastes here
 * -- but there is no session to require, because the whole point is that no
 * session can be obtained.
 *
 * On success the returned token becomes the ordinary session cookie, so the
 * emergency session behaves like any other for the rest of the dashboard while
 * remaining marked, short-lived, and under review server side.
 */
export async function handleActivateBreakGlass(
  request: Request,
  dependencies: {
    activate: (body: unknown) => Promise<UpstreamResult>;
  },
): Promise<AdminSessionRouteResult> {
  if (!sameOrigin(request)) return fail("request-rejected", 403);

  const body = await readBody(request);
  const credential = validateCredential(field(body, "credential"));
  const reason = validateReason(field(body, "reason"));
  if (credential === null || reason === null) return fail("invalid-request", 400);

  const upstream = await dependencies.activate({ credential, reason });
  if (upstream.status !== 200) return upstreamFailure(upstream);

  const token = (upstream.body as Record<string, unknown> | undefined)?.access_token;
  if (typeof token !== "string" || token.length === 0) {
    return fail("unavailable", 503);
  }
  return {
    response: json({ ok: true }),
    cookies: [
      { name: sessionCookieName(), value: token, options: sessionCookieOptions() },
    ],
  };
}
