// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import { cookies } from "next/headers";

import { mfaCookieName } from "@/lib/mfa-core";
import { NodelinkApiError, nodelinkApiRequest } from "@/lib/nodelink-api";
import type { MfaStatus } from "@/lib/mfa-core";

/**
 * Server-side calls to the NodeLink MFA API (issue #67).
 *
 * Every helper returns `{ status, code, body }` rather than throwing, because
 * the route handlers in `mfa-route-core.ts` need to *decide* on a non-2xx
 * response (a 429 is a rate limit to surface, a 403 with `step_up_required` is
 * a prompt to re-assert) rather than treat it as an exception. Shaping the
 * result here keeps that decision in one testable place.
 */

type UpstreamResult = { status: number; code?: string | null; body?: unknown };

async function call(
  path: string,
  token: string,
  init: { method: string; body?: unknown },
  successStatus = 200,
): Promise<UpstreamResult> {
  try {
    const body = await nodelinkApiRequest<unknown>(path, {
      method: init.method,
      sessionToken: token,
      ...(init.body === undefined
        ? {}
        : {
          body: JSON.stringify(init.body),
          headers: { "Content-Type": "application/json" },
        }),
    });
    return { status: successStatus, body };
  } catch (error) {
    if (error instanceof NodelinkApiError) {
      return { status: error.status, code: error.code };
    }
    // A transport failure is an availability problem, not a refusal. 503 keeps
    // it distinguishable from an upstream decision.
    return { status: 503, code: null };
  }
}

/** Read the restricted post-password token from its own cookie. */
export async function readMfaCookie(): Promise<string | undefined> {
  const store = await cookies();
  return store.get(mfaCookieName())?.value;
}

export const fetchLoginOptions = (token: string) =>
  call("/api/v1/auth/mfa/login/options", token, { method: "POST" });

export const verifyLoginAssertion = (token: string, body?: unknown) =>
  call("/api/v1/auth/mfa/login/verify", token, { method: "POST", body });

export const verifyRecoveryCode = (token: string, body?: unknown) =>
  call("/api/v1/auth/mfa/login/recovery-code", token, { method: "POST", body });

export const sendLoginEmailCode = (token: string) =>
  call("/api/v1/auth/mfa/login/email/send", token, { method: "POST" });

export const verifyLoginEmailCode = (token: string, body?: unknown) =>
  call("/api/v1/auth/mfa/login/email/verify", token, { method: "POST", body });

export const startEmailEnrollment = (token: string) =>
  call("/api/v1/auth/mfa/email/enrollment/start", token, { method: "POST" });

export const verifyEmailEnrollment = (token: string, body?: unknown) =>
  call("/api/v1/auth/mfa/email/enrollment/verify", token, { method: "POST", body });

export const removeEmailFactor = (token: string, body: unknown) =>
  call("/api/v1/auth/mfa/email", token, { method: "POST", body });

export const fetchRegistrationOptions = (token: string) =>
  call("/api/v1/auth/mfa/credentials/options", token, { method: "POST" });

export const registerCredential = (token: string, body?: unknown) =>
  call("/api/v1/auth/mfa/credentials", token, { method: "POST", body }, 201);

export const renameCredential = (token: string, id: string, body: unknown) =>
  call(`/api/v1/auth/mfa/credentials/${encodeURIComponent(id)}`, token, {
    method: "PUT",
    body,
  });

export const revokeCredential = (token: string, id: string, body: unknown) =>
  call(`/api/v1/auth/mfa/credentials/${encodeURIComponent(id)}/revoke`, token, {
    method: "POST",
    body,
  });

export const generateRecoveryCodes = (token: string) =>
  call("/api/v1/auth/mfa/recovery-codes", token, { method: "POST" });

export const fetchStepUpOptions = (token: string) =>
  call("/api/v1/auth/mfa/step-up/options", token, { method: "POST" });

export const verifyStepUp = (token: string, body?: unknown) =>
  call("/api/v1/auth/mfa/step-up/verify", token, { method: "POST", body });

/**
 * Read the operator's MFA state for server-rendered pages.
 *
 * Returns null when the API cannot answer, so a page can render a degraded
 * banner rather than failing outright — the same "unavailable" treatment
 * `getDashboardSession` already applies.
 */
export async function fetchMfaStatus(sessionToken: string): Promise<MfaStatus | null> {
  try {
    return await nodelinkApiRequest<MfaStatus>("/api/v1/auth/mfa/status", {
      method: "GET",
      sessionToken,
    });
  } catch {
    return null;
  }
}
