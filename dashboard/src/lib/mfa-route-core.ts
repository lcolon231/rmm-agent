// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Route handlers for the dashboard's MFA proxy endpoints (issue #67).
 *
 * Dependencies are injected rather than imported so every handler is testable
 * without a running server, matching `operator-management-route-core.ts`.
 *
 * Two invariants hold across every handler here:
 *
 * 1. **No credential ever reaches the browser.** The session token and the
 *    restricted MFA token live in HTTP-only cookies that this layer reads and
 *    writes; the client sends ceremony bytes and gets back a rendered outcome.
 *    That is why these proxy routes exist at all rather than the browser
 *    talking to the API directly.
 * 2. **Every mutating request is same-origin checked** before a credential is
 *    attached to an upstream call, so a cross-site request cannot spend the
 *    caller's cookie.
 */

import { isSameOrigin, requestOrigin, sessionCookieName, sessionCookieOptions } from "./dashboard-auth-core.ts";
import {
  clearedMfaCookieOptions,
  mfaCookieName,
  mfaCookieOptions,
  mfaErrorCodeForStatus,
  mfaErrorMessage,
  readLoginChallenge,
  validateDeviceName,
  validateEmailCode,
  validateRecoveryCode,
  validateRevokeReason,
  type MfaErrorCode,
} from "./mfa-core.ts";

type RouteSession =
  | { kind: "anonymous" }
  | { kind: "unavailable" }
  | { kind: "authenticated"; operator: { role: string }; sessionToken: string };

export type UpstreamCall = (
  token: string,
  body?: unknown,
) => Promise<{ status: number; code?: string | null; body?: unknown }>;

export type MfaRouteDependencies = {
  getSession: () => Promise<RouteSession>;
  /** Reads the restricted post-password token from its cookie. */
  getMfaToken: () => Promise<string | undefined>;
};

type CookieInstruction = {
  name: string;
  value: string;
  options: Record<string, unknown>;
};

/**
 * A response plus the cookies the caller must set on it.
 *
 * Returned rather than applied because `cookies()` is a Next server-runtime
 * concern; keeping it out of this file is what makes the handlers testable.
 */
export type MfaRouteResult = {
  response: Response;
  cookies: CookieInstruction[];
};

function json(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

function errorResult(code: MfaErrorCode, status: number): MfaRouteResult {
  return {
    response: json({ error: mfaErrorMessage(code), code }, status),
    cookies: [],
  };
}

function isSameOriginRequest(request: Request): boolean {
  return isSameOrigin(
    request.headers.get("origin"),
    requestOrigin(request.url, request.headers.get("host")),
  );
}

async function readJsonBody(request: Request): Promise<unknown | undefined> {
  try {
    return await request.json();
  } catch {
    return undefined;
  }
}

async function requireSessionToken(
  dependencies: MfaRouteDependencies,
): Promise<string | MfaRouteResult> {
  let session: RouteSession;
  try {
    session = await dependencies.getSession();
  } catch {
    return errorResult("unavailable", 503);
  }
  if (session.kind === "unavailable") {
    return errorResult("unavailable", 503);
  }
  if (session.kind !== "authenticated") {
    return errorResult("request-rejected", 401);
  }
  return session.sessionToken;
}

async function requireMfaToken(
  dependencies: MfaRouteDependencies,
): Promise<string | MfaRouteResult> {
  const token = await dependencies.getMfaToken();
  if (!token) {
    // No half-finished login is in progress. Returning 401 rather than a
    // redirect keeps this endpoint's contract uniform for its only caller.
    return errorResult("request-rejected", 401);
  }
  return token;
}

function upstreamFailure(status: number, code?: string | null): MfaRouteResult {
  const errorCode = mfaErrorCodeForStatus(status, code);
  // Upstream 4xx are surfaced as themselves so the client can distinguish a
  // rate limit from a refusal; anything else becomes a 503, because an
  // unexpected upstream status is an availability problem, not the caller's.
  const responseStatus = status === 429 || status === 401 || status === 400 || status === 403
    ? status
    : 503;
  return errorResult(errorCode, responseStatus);
}

// --------------------------------------------------------------------------- //
// Login completion
// --------------------------------------------------------------------------- //
/** Fetch assertion options using the restricted post-password token. */
export async function handleLoginOptions(
  request: Request,
  dependencies: MfaRouteDependencies & { fetchOptions: UpstreamCall },
): Promise<MfaRouteResult> {
  if (!isSameOriginRequest(request)) {
    return errorResult("request-rejected", 403);
  }
  const token = await requireMfaToken(dependencies);
  if (typeof token !== "string") {
    return token;
  }

  const upstream = await dependencies.fetchOptions(token);
  if (upstream.status !== 200) {
    return upstreamFailure(upstream.status, upstream.code);
  }
  return { response: json(upstream.body), cookies: [] };
}

/**
 * Complete a login with either an assertion or a recovery code.
 *
 * On success the restricted cookie is deleted and the session cookie is set in
 * the same response, so the browser is never holding both at once.
 */
export async function handleLoginVerify(
  request: Request,
  dependencies: MfaRouteDependencies & {
    verify: UpstreamCall;
    kind: "webauthn" | "recovery_code" | "email_code";
  },
): Promise<MfaRouteResult> {
  if (!isSameOriginRequest(request)) {
    return errorResult("request-rejected", 403);
  }
  const token = await requireMfaToken(dependencies);
  if (typeof token !== "string") {
    return token;
  }

  const body = await readJsonBody(request);
  const payload = dependencies.kind === "recovery_code"
    ? recoveryPayload(body)
    : dependencies.kind === "email_code"
      ? emailCodePayload(body)
      : assertionPayload(body);
  if (payload === null) {
    return errorResult("invalid-request", 400);
  }

  const upstream = await dependencies.verify(token, payload);
  if (upstream.status !== 200) {
    const failure = upstreamFailure(upstream.status, upstream.code);
    // A refused attempt keeps the restricted cookie so the operator can retry
    // (or fall back to a recovery code) without re-entering their password.
    return failure;
  }

  const accessToken = readAccessToken(upstream.body);
  if (!accessToken) {
    return errorResult("unavailable", 503);
  }
  return {
    response: json({ ok: true }),
    cookies: [
      { name: sessionCookieName(), value: accessToken, options: sessionCookieOptions() },
      { name: mfaCookieName(), value: "", options: clearedMfaCookieOptions() },
    ],
  };
}

function readAccessToken(body: unknown): string | null {
  if (!body || typeof body !== "object") {
    return null;
  }
  const token = (body as Record<string, unknown>).access_token;
  return typeof token === "string" && token.length > 0 ? token : null;
}

function assertionPayload(body: unknown): Record<string, string> | null {
  if (!body || typeof body !== "object") {
    return null;
  }
  const record = body as Record<string, unknown>;
  const fields = ["credential_id", "client_data_json", "authenticator_data", "signature"];
  const payload: Record<string, string> = {};
  for (const field of fields) {
    const value = record[field];
    if (typeof value !== "string" || value.length === 0 || value.length > 32 * 1024) {
      return null;
    }
    payload[field] = value;
  }
  return payload;
}

function emailCodePayload(body: unknown): Record<string, string> | null {
  const code = validateEmailCode(
    body && typeof body === "object" ? (body as Record<string, unknown>).code : null,
  );
  return code === null ? null : { code };
}

function recoveryPayload(body: unknown): Record<string, string> | null {
  const code = validateRecoveryCode(
    body && typeof body === "object" ? (body as Record<string, unknown>).code : null,
  );
  return code === null ? null : { code };
}

// --------------------------------------------------------------------------- //
// Enrolment
// --------------------------------------------------------------------------- //
/**
 * Begin registration.
 *
 * Accepts either credential: a signed-in operator adding a device presents a
 * session, while an operator whom policy requires to enrol has only the
 * restricted token. Preferring the session when both exist matches the server,
 * which treats the restricted token as an enrolment credential only for an
 * operator who has no other way in.
 */
export async function handleRegistrationOptions(
  request: Request,
  dependencies: MfaRouteDependencies & { fetchOptions: UpstreamCall },
): Promise<MfaRouteResult> {
  if (!isSameOriginRequest(request)) {
    return errorResult("request-rejected", 403);
  }
  const token = await enrolmentToken(dependencies);
  if (typeof token !== "string") {
    return token;
  }
  const upstream = await dependencies.fetchOptions(token);
  if (upstream.status !== 200) {
    return upstreamFailure(upstream.status, upstream.code);
  }
  return { response: json(upstream.body), cookies: [] };
}

/** Complete registration, and promote the restricted token when that was it. */
export async function handleRegisterCredential(
  request: Request,
  dependencies: MfaRouteDependencies & { register: UpstreamCall },
): Promise<MfaRouteResult> {
  if (!isSameOriginRequest(request)) {
    return errorResult("request-rejected", 403);
  }
  const token = await enrolmentToken(dependencies);
  if (typeof token !== "string") {
    return token;
  }

  const body = await readJsonBody(request);
  const record = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const name = validateDeviceName(record.name);
  const clientData = record.client_data_json;
  const attestation = record.attestation_object;
  if (
    name === null
    || typeof clientData !== "string"
    || typeof attestation !== "string"
    || clientData.length === 0
    || attestation.length === 0
    || attestation.length > 64 * 1024
  ) {
    return errorResult("invalid-request", 400);
  }

  const transports = Array.isArray(record.transports)
    ? record.transports.filter((entry): entry is string => typeof entry === "string").slice(0, 8)
    : undefined;

  const upstream = await dependencies.register(token, {
    name,
    client_data_json: clientData,
    attestation_object: attestation,
    ...(transports && transports.length > 0 ? { transports } : {}),
  });
  if (upstream.status !== 201) {
    return upstreamFailure(upstream.status, upstream.code);
  }
  return { response: json(upstream.body, 201), cookies: [] };
}

async function enrolmentToken(
  dependencies: MfaRouteDependencies,
): Promise<string | MfaRouteResult> {
  let session: RouteSession = { kind: "anonymous" };
  try {
    session = await dependencies.getSession();
  } catch {
    return errorResult("unavailable", 503);
  }
  if (session.kind === "authenticated") {
    return session.sessionToken;
  }
  const pending = await dependencies.getMfaToken();
  if (pending) {
    return pending;
  }
  if (session.kind === "unavailable") {
    return errorResult("unavailable", 503);
  }
  return errorResult("request-rejected", 401);
}

// --------------------------------------------------------------------------- //
// Device management and step-up
// --------------------------------------------------------------------------- //
export async function handleRenameCredential(
  request: Request,
  credentialId: string,
  dependencies: MfaRouteDependencies & { rename: (token: string, id: string, body: unknown) => ReturnType<UpstreamCall> },
): Promise<MfaRouteResult> {
  if (!isSameOriginRequest(request)) {
    return errorResult("request-rejected", 403);
  }
  const token = await requireSessionToken(dependencies);
  if (typeof token !== "string") {
    return token;
  }
  const body = await readJsonBody(request);
  const name = validateDeviceName(
    body && typeof body === "object" ? (body as Record<string, unknown>).name : null,
  );
  if (name === null) {
    return errorResult("invalid-request", 400);
  }
  const upstream = await dependencies.rename(token, credentialId, { name });
  if (upstream.status !== 200) {
    return upstreamFailure(upstream.status, upstream.code);
  }
  return { response: json(upstream.body), cookies: [] };
}

export async function handleRevokeCredential(
  request: Request,
  credentialId: string,
  dependencies: MfaRouteDependencies & { revoke: (token: string, id: string, body: unknown) => ReturnType<UpstreamCall> },
): Promise<MfaRouteResult> {
  if (!isSameOriginRequest(request)) {
    return errorResult("request-rejected", 403);
  }
  const token = await requireSessionToken(dependencies);
  if (typeof token !== "string") {
    return token;
  }
  const body = await readJsonBody(request);
  const reason = validateRevokeReason(
    body && typeof body === "object" ? (body as Record<string, unknown>).reason : null,
  );
  if (reason === null) {
    return errorResult("invalid-request", 400);
  }
  const upstream = await dependencies.revoke(token, credentialId, { reason });
  if (upstream.status !== 200) {
    return upstreamFailure(upstream.status, upstream.code);
  }
  return { response: json(upstream.body), cookies: [] };
}

/**
 * Mint recovery codes.
 *
 * The plaintext codes pass through to the browser exactly once and are
 * deliberately not cached, stored, or logged anywhere in this layer — the
 * `Cache-Control: no-store` on every response here is part of that.
 */
export async function handleGenerateRecoveryCodes(
  request: Request,
  dependencies: MfaRouteDependencies & { generate: UpstreamCall },
): Promise<MfaRouteResult> {
  if (!isSameOriginRequest(request)) {
    return errorResult("request-rejected", 403);
  }
  const token = await requireSessionToken(dependencies);
  if (typeof token !== "string") {
    return token;
  }
  const upstream = await dependencies.generate(token);
  if (upstream.status !== 200) {
    return upstreamFailure(upstream.status, upstream.code);
  }
  return { response: json(upstream.body), cookies: [] };
}

/**
 * Request that a one-time code be mailed (issue #226).
 *
 * `credential` selects which token the send is authorised with: the restricted
 * post-password cookie during a login, or the operator's session while
 * enrolling from the security page.
 *
 * The upstream acknowledgement is passed through as-is. It is deliberately the
 * same shape whether or not the operator actually has an email factor, and this
 * layer must not "helpfully" turn the two into different client outcomes.
 */
export async function handleSendEmailCode(
  request: Request,
  dependencies: MfaRouteDependencies & {
    send: UpstreamCall;
    credential: "mfa-token" | "session";
  },
): Promise<MfaRouteResult> {
  if (!isSameOriginRequest(request)) {
    return errorResult("request-rejected", 403);
  }
  const token = dependencies.credential === "mfa-token"
    ? await requireMfaToken(dependencies)
    : await requireSessionToken(dependencies);
  if (typeof token !== "string") {
    return token;
  }
  const upstream = await dependencies.send(token);
  if (upstream.status !== 200) {
    return upstreamFailure(upstream.status, upstream.code);
  }
  return { response: json(upstream.body), cookies: [] };
}

/**
 * Confirm an emailed enrolment code, or remove the factor.
 *
 * Both are ordinary session-authorised mutations that return the resulting
 * factor state, so they share one handler shaped by `payload`.
 */
export async function handleEmailFactorMutation(
  request: Request,
  dependencies: MfaRouteDependencies & {
    mutate: UpstreamCall;
    payload: "code" | "reason";
  },
): Promise<MfaRouteResult> {
  if (!isSameOriginRequest(request)) {
    return errorResult("request-rejected", 403);
  }
  const token = await requireSessionToken(dependencies);
  if (typeof token !== "string") {
    return token;
  }
  const body = await readJsonBody(request);
  const record = body && typeof body === "object" ? (body as Record<string, unknown>) : {};
  const payload = dependencies.payload === "code"
    ? emailCodePayload(record)
    : (() => {
      const reason = validateRevokeReason(record.reason);
      return reason === null ? null : { reason };
    })();
  if (payload === null) {
    return errorResult("invalid-request", 400);
  }
  const upstream = await dependencies.mutate(token, payload);
  if (upstream.status !== 200) {
    return upstreamFailure(upstream.status, upstream.code);
  }
  return { response: json(upstream.body), cookies: [] };
}

export async function handleStepUpOptions(
  request: Request,
  dependencies: MfaRouteDependencies & { fetchOptions: UpstreamCall },
): Promise<MfaRouteResult> {
  if (!isSameOriginRequest(request)) {
    return errorResult("request-rejected", 403);
  }
  const token = await requireSessionToken(dependencies);
  if (typeof token !== "string") {
    return token;
  }
  const upstream = await dependencies.fetchOptions(token);
  if (upstream.status !== 200) {
    return upstreamFailure(upstream.status, upstream.code);
  }
  return { response: json(upstream.body), cookies: [] };
}

/**
 * Complete a step-up and swap in the upgraded session token.
 *
 * The server returns a *new* token carrying the step-up claim; replacing the
 * cookie is what makes the next sensitive request succeed. The old token stays
 * valid upstream until it expires, so a concurrent tab is not logged out.
 */
export async function handleStepUpVerify(
  request: Request,
  dependencies: MfaRouteDependencies & { verify: UpstreamCall },
): Promise<MfaRouteResult> {
  if (!isSameOriginRequest(request)) {
    return errorResult("request-rejected", 403);
  }
  const token = await requireSessionToken(dependencies);
  if (typeof token !== "string") {
    return token;
  }
  const payload = assertionPayload(await readJsonBody(request));
  if (payload === null) {
    return errorResult("invalid-request", 400);
  }
  const upstream = await dependencies.verify(token, payload);
  if (upstream.status !== 200) {
    return upstreamFailure(upstream.status, upstream.code);
  }
  const accessToken = readAccessToken(upstream.body);
  if (!accessToken) {
    return errorResult("unavailable", 503);
  }
  return {
    response: json({ ok: true }),
    cookies: [
      { name: sessionCookieName(), value: accessToken, options: sessionCookieOptions() },
    ],
  };
}

// --------------------------------------------------------------------------- //
// Login hand-off
// --------------------------------------------------------------------------- //
/**
 * Translate a `/auth/login` success body into the cookies and response the
 * browser should receive.
 *
 * Kept here, beside the MFA handlers, because it is the one place the login
 * route has to know about the challenge state, and testing it next to
 * `readLoginChallenge` keeps the two in step.
 */
export function loginOutcome(body: unknown): MfaRouteResult | null {
  const challenge = readLoginChallenge(body);
  if (challenge === null) {
    return null;
  }
  return {
    response: json({
      mfa_required: true,
      mfa_enrollment_required: challenge.enrollmentRequired,
      mfa_methods: challenge.methods,
    }),
    cookies: [
      { name: mfaCookieName(), value: challenge.mfaToken, options: mfaCookieOptions() },
      // Any stale session is cleared: a login that owes a second factor must
      // not leave the browser holding a previous, fully-privileged session.
      { name: sessionCookieName(), value: "", options: { ...sessionCookieOptions(), maxAge: 0 } },
    ],
  };
}
