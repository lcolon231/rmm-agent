// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import { NodelinkApiError, nodelinkApiRequest } from "@/lib/nodelink-api";
import type { UpstreamResult } from "@/lib/admin-sessions-route-core";
import type {
  BreakGlassAccountRecord,
  BreakGlassActivationRecord,
  BreakGlassStatus,
  SessionRecord,
} from "@/lib/admin-sessions-core";

/**
 * Server-side calls for sessions and break-glass (issue #69).
 *
 * Each helper returns `{ status, code, body }` rather than throwing, because
 * the route handlers must *decide* on a non-2xx: a 403 with `step_up_required`
 * is a prompt to re-assert, a 409 on review means someone else already signed
 * it off, and a 429 on activation is a rate limit worth surfacing verbatim.
 */

async function call(
  path: string,
  init: { method: string; body?: unknown },
  token: string | null,
  successStatus = 200,
): Promise<UpstreamResult> {
  try {
    const body = await nodelinkApiRequest<unknown>(path, {
      method: init.method,
      // The activation endpoint is unauthenticated upstream; the API helper
      // still requires a non-empty bearer, so a sentinel is sent and ignored.
      sessionToken: token ?? "break-glass-activation",
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
    return { status: 503, code: null };
  }
}

export const listOwnSessions = (token: string) =>
  call("/api/v1/auth/sessions?include_ended=true", { method: "GET" }, token);

export const revokeOwnSession = (token: string, id: string, body: unknown) =>
  call(`/api/v1/auth/sessions/${encodeURIComponent(id)}/revoke`, { method: "POST", body }, token);

export const revokeOtherOwnSessions = (token: string, body: unknown) =>
  call("/api/v1/auth/sessions/revoke-others", { method: "POST", body }, token);

export const listBreakGlassAccounts = (token: string) =>
  call("/api/v1/auth/break-glass", { method: "GET" }, token);

export const createBreakGlassAccount = (token: string, body: unknown) =>
  call("/api/v1/auth/break-glass", { method: "POST", body }, token, 201);

export const rotateBreakGlassCredential = (token: string, id: string, body: unknown) =>
  call(`/api/v1/auth/break-glass/${encodeURIComponent(id)}/rotate`, { method: "POST", body }, token);

export const setBreakGlassDisabled = (token: string, id: string, body: unknown) =>
  call(`/api/v1/auth/break-glass/${encodeURIComponent(id)}/disabled`, { method: "PUT", body }, token);

export const reviewBreakGlassActivation = (token: string, id: string, body: unknown) =>
  call(
    `/api/v1/auth/break-glass/activations/${encodeURIComponent(id)}/review`,
    { method: "POST", body },
    token,
  );

export const activateBreakGlass = (body: unknown) =>
  call("/api/v1/auth/break-glass/activate", { method: "POST", body }, null);

/** Read helpers for server-rendered pages. Null means "could not answer". */
async function read<T>(path: string, token: string): Promise<T | null> {
  try {
    return await nodelinkApiRequest<T>(path, { method: "GET", sessionToken: token });
  } catch {
    return null;
  }
}

export const fetchOwnSessions = (token: string) =>
  read<SessionRecord[]>("/api/v1/auth/sessions?include_ended=true", token);

export const fetchBreakGlassAccounts = (token: string) =>
  read<BreakGlassAccountRecord[]>("/api/v1/auth/break-glass", token);

export const fetchBreakGlassStatus = (token: string) =>
  read<BreakGlassStatus>("/api/v1/auth/break-glass/status", token);

export const fetchBreakGlassActivations = (token: string) =>
  read<BreakGlassActivationRecord[]>("/api/v1/auth/break-glass/activations", token);
