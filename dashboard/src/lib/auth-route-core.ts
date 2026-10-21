// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Route cores for sign-in, sign-out, the MFA status read, the break-glass
 * activation history, and the health probe (issue #280).
 *
 * Cookies come back as instructions (`MfaRouteResult`) for the adapter to
 * apply, exactly as the MFA handlers do, so nothing here needs a Next runtime.
 */

import {
  authorizeSession,
  isRecord,
  isSameOriginRequest,
  json,
  type GetSession,
} from "./bff-route-core.ts";
import {
  loginErrorMessage,
  readLoginSubmission,
  requestOrigin,
  sessionCookieName,
  sessionCookieOptions,
  validateLoginCredentials,
  type DashboardOperator,
  type LoginCredentials,
  type LoginErrorCode,
} from "./dashboard-auth-core.ts";
import { readLoginChallenge, type MfaStatus } from "./mfa-core.ts";
import { loginOutcome, type MfaRouteResult } from "./mfa-route-core.ts";
import type { BreakGlassActivationRecord } from "./admin-sessions-core.ts";

/** What a password check produced, so the core never sees a thrown class. */
export type LoginAttempt =
  | { kind: "authenticated"; operator: DashboardOperator; sessionToken: string }
  | { kind: "second-factor"; body: unknown }
  | { kind: "rejected"; status: number };

const noCookies = (response: Response): MfaRouteResult => ({ response, cookies: [] });

function clearedSessionCookie() {
  return { name: sessionCookieName(), value: "", options: { ...sessionCookieOptions(), maxAge: 0 } };
}

function loginError(
  origin: string,
  kind: "form" | "json",
  code: LoginErrorCode,
  status: number,
): MfaRouteResult {
  if (kind === "form") {
    const loginUrl = new URL("/login", origin);
    loginUrl.searchParams.set("error", code);
    return noCookies(Response.redirect(loginUrl, 303));
  }
  return noCookies(json({ error: loginErrorMessage(code) ?? "Sign-in is unavailable. Try again later." }, status));
}

export async function handleLogin(
  request: Request,
  deps: { authenticate: (credentials: LoginCredentials) => Promise<LoginAttempt> },
): Promise<MfaRouteResult> {
  const submission = await readLoginSubmission(request);
  const kind = submission?.kind ?? "json";
  const origin = requestOrigin(request.url, request.headers.get("host"));

  if (!isSameOriginRequest(request)) return loginError(origin, kind, "request-rejected", 403);
  const credentials = submission ? validateLoginCredentials(submission.body) : null;
  if (!credentials) return loginError(origin, kind, "invalid-request", 400);

  let attempt: LoginAttempt;
  try {
    attempt = await deps.authenticate(credentials);
  } catch {
    return loginError(origin, kind, "unavailable", 503);
  }

  if (attempt.kind === "authenticated") {
    const { id, email, role, disabled } = attempt.operator;
    const response = kind === "form"
      ? Response.redirect(new URL("/", origin), 303)
      : json({ operator: { id, email, role, disabled } });
    return {
      response,
      cookies: [{ name: sessionCookieName(), value: attempt.sessionToken, options: sessionCookieOptions() }],
    };
  }

  if (attempt.kind === "second-factor") {
    // The password was correct but a second factor is owed: stash the
    // restricted token in its own cookie and send the caller to the challenge,
    // never to "/", which would suggest a session that does not exist.
    const outcome = loginOutcome(attempt.body);
    const challenge = readLoginChallenge(attempt.body);
    if (outcome === null || challenge === null) return loginError(origin, kind, "unavailable", 503);
    if (kind === "json") return outcome;
    const challengeUrl = new URL("/login/mfa", origin);
    if (challenge.methods.length > 0) challengeUrl.searchParams.set("methods", challenge.methods.join(","));
    if (challenge.enrollmentRequired) challengeUrl.searchParams.set("enroll", "1");
    return { response: Response.redirect(challengeUrl, 303), cookies: outcome.cookies };
  }

  const status = attempt.status === 429 ? 429 : attempt.status === 401 ? 401 : 503;
  const code: LoginErrorCode = status === 401 ? "invalid-credentials" : status === 429 ? "rate-limited" : "unavailable";
  return loginError(origin, kind, code, status);
}

/**
 * Sign out. The cookie is always cleared; the token is revoked upstream only
 * when `/auth/me` confirms it is still live, so a dead or unverifiable cookie
 * is never forwarded.
 */
export async function handleLogout(
  request: Request,
  deps: { getSession: GetSession; revokeOperatorTokens: (sessionToken: string) => Promise<void> },
): Promise<MfaRouteResult> {
  if (!isSameOriginRequest(request)) return noCookies(json({ error: "Sign-out request was rejected." }, 403));

  const cookies = [clearedSessionCookie()];
  const unrevoked = json({ error: "Signed out locally; token revocation was unavailable." }, 503);
  let session: Awaited<ReturnType<GetSession>>;
  try {
    session = await deps.getSession();
  } catch {
    return { response: unrevoked, cookies };
  }
  if (session.kind === "anonymous") return { response: json({ status: "signed_out" }), cookies };
  if (session.kind === "unavailable") return { response: unrevoked, cookies };
  try {
    await deps.revokeOperatorTokens(session.sessionToken);
    return { response: json({ status: "signed_out" }), cookies };
  } catch {
    return { response: unrevoked, cookies };
  }
}

function stringOrNull(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

export function mfaStatusFromUnknown(value: unknown): MfaStatus | null {
  if (!isRecord(value)) return null;
  const enforcement = value.enforcement;
  if (enforcement !== "off" && enforcement !== "optional" && enforcement !== "required") return null;
  if (!Array.isArray(value.credentials) || !Array.isArray(value.session_methods)) return null;
  const credentials: MfaStatus["credentials"] = [];
  for (const item of value.credentials) {
    if (!isRecord(item) || typeof item.id !== "string" || typeof item.name !== "string") return null;
    credentials.push({
      id: item.id,
      name: item.name,
      algorithm: typeof item.algorithm === "number" ? item.algorithm : 0,
      aaguid: typeof item.aaguid === "string" ? item.aaguid : "",
      transports: stringOrNull(item.transports),
      attestation_format: typeof item.attestation_format === "string" ? item.attestation_format : "",
      backup_eligible: item.backup_eligible === true,
      backup_state: item.backup_state === true,
      created_at: typeof item.created_at === "string" ? item.created_at : "",
      last_used_at: stringOrNull(item.last_used_at),
    });
  }
  const count = (field: unknown) => (Number.isSafeInteger(field) && Number(field) >= 0 ? Number(field) : 0);
  const status: MfaStatus = {
    enforcement,
    enrollment_required: value.enrollment_required === true,
    enrolled: value.enrolled === true,
    credential_count: count(value.credential_count),
    recovery_codes_remaining: count(value.recovery_codes_remaining),
    step_up_satisfied: value.step_up_satisfied === true,
    session_methods: value.session_methods.filter((method): method is string => typeof method === "string"),
    credentials,
  };
  const policy = value.email_code_policy;
  if (policy === "off" || policy === "fallback_only" || policy === "always") status.email_code_policy = policy;
  if (isRecord(value.email_factor)) {
    status.email_factor = {
      verified: value.email_factor.verified === true,
      destination: stringOrNull(value.email_factor.destination),
      verified_at: stringOrNull(value.email_factor.verified_at),
    };
  } else if (value.email_factor === null) {
    status.email_factor = null;
  }
  return status;
}

export async function handleMfaStatus(
  _request: Request,
  deps: { getSession: GetSession; fetchMfaStatus: (sessionToken: string) => Promise<unknown> },
): Promise<Response> {
  // GET, scoped to the caller's own session: no origin check, any role.
  const auth = await authorizeSession(deps.getSession, {
    minRole: "readonly",
    signedOut: "Sign in to view your security settings.",
    forbidden: "Sign in to view your security settings.",
  });
  if (auth instanceof Response) return auth;
  const status = mfaStatusFromUnknown(await deps.fetchMfaStatus(auth.sessionToken).catch(() => null));
  return status ? json(status) : json({ error: "Your multi-factor state is unavailable. Try again." }, 503);
}

export function activationsFromUnknown(value: unknown): BreakGlassActivationRecord[] | null {
  if (!Array.isArray(value)) return null;
  const activations: BreakGlassActivationRecord[] = [];
  for (const item of value) {
    if (
      !isRecord(item) || typeof item.id !== "string" || typeof item.account_id !== "string"
      || typeof item.activated_at !== "string" || typeof item.reason !== "string"
    ) return null;
    activations.push({
      id: item.id,
      account_id: item.account_id,
      session_id: stringOrNull(item.session_id),
      activated_at: item.activated_at,
      source_ip: stringOrNull(item.source_ip),
      user_agent: stringOrNull(item.user_agent),
      reason: item.reason,
      reviewed_at: stringOrNull(item.reviewed_at),
      reviewed_by_email: stringOrNull(item.reviewed_by_email),
      review_note: stringOrNull(item.review_note),
    });
  }
  return activations;
}

export async function handleBreakGlassActivations(
  _request: Request,
  deps: { getSession: GetSession; fetchBreakGlassActivations: (sessionToken: string) => Promise<unknown> },
): Promise<Response> {
  // GET only; the upstream additionally requires a platform admin.
  const auth = await authorizeSession(deps.getSession, {
    minRole: "admin",
    signedOut: "Sign in to view break-glass activations.",
    forbidden: "Only an administrator can view break-glass activations.",
  });
  if (auth instanceof Response) return auth;
  const activations = activationsFromUnknown(
    await deps.fetchBreakGlassActivations(auth.sessionToken).catch(() => null),
  );
  return activations
    ? json(activations)
    : json({ error: "Break-glass activations are unavailable, or your role cannot see them." }, 503);
}

/** Unauthenticated liveness probe: one bit out, never an upstream detail. */
export async function handleHealth(deps: { checkHealth: () => Promise<"ok" | "degraded"> }): Promise<Response> {
  try {
    if ((await deps.checkHealth()) === "ok") return Response.json({ status: "ok" });
  } catch {
    // Configuration and upstream failures intentionally share one response.
  }
  return Response.json({ status: "degraded" }, { status: 503 });
}
