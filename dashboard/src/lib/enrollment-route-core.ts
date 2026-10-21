// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Route cores for enrollment trust changes and the installer download
 * (issue #280).
 *
 * Token creation and revocation and the installer download need the operator
 * role (the service's floor); revoking an agent's credentials is admin-only.
 * The created-token response carries the one-time plaintext token, so it is
 * rebuilt field by field: nothing the API adds later rides along with it.
 */

import {
  authorizeSession,
  isRecord,
  isSameOriginRequest,
  json,
  readJsonBody,
  upstreamError,
  type GetSession,
} from "./bff-route-core.ts";
import { installerDownloadError, installerDownloadFilename } from "./installer-download-core.ts";

const SIGNED_OUT = "Sign in again to continue.";

const CREATE_FIELDS = [
  "site_id",
  "name",
  "description",
  "assigned_user_id",
  "environment",
  "hostname_restriction",
  "agent_name_restriction",
  "labels",
  "expires_at",
  "max_uses",
  "notes",
] as const;

const STRING_FIELDS = [
  "id", "site_id", "organization_id", "organization_name", "site_name", "masked_token", "name",
  "created_at", "status",
] as const;
const NULLABLE_STRING_FIELDS = [
  "description", "assigned_user_id", "assigned_user_email", "environment", "hostname_restriction",
  "agent_name_restriction", "expires_at", "created_by_id", "created_by_email", "last_used_at",
  "revoked_at", "revoked_by_id", "revoked_by_email", "notes",
] as const;

export function tokenCreateInputFromUnknown(value: unknown): Record<string, unknown> | null {
  if (!isRecord(value)) return null;
  const input: Record<string, unknown> = {};
  for (const field of CREATE_FIELDS) {
    if (field in value) input[field] = value[field];
  }
  return input;
}

/** Allowlist the creation-only token record (metadata plus plaintext). */
export function createdTokenFromUnknown(value: unknown): Record<string, unknown> | null {
  if (!isRecord(value) || typeof value.token !== "string" || value.token === "") return null;
  const token: Record<string, unknown> = { token: value.token };
  for (const field of STRING_FIELDS) {
    if (typeof value[field] !== "string") return null;
    token[field] = value[field];
  }
  for (const field of NULLABLE_STRING_FIELDS) {
    token[field] = typeof value[field] === "string" ? value[field] : null;
  }
  if (!Number.isSafeInteger(value.max_uses) || !Number.isSafeInteger(value.use_count)) return null;
  token.max_uses = value.max_uses;
  token.use_count = value.use_count;
  token.labels = Array.isArray(value.labels)
    ? value.labels.filter((label): label is string => typeof label === "string")
    : [];
  return token;
}

/** The audit reason the service requires for every trust transition. */
export function trustChangeReasonFromUnknown(value: unknown): string | null {
  if (!isRecord(value) || typeof value.reason !== "string") return null;
  const reason = value.reason.trim();
  return reason.length >= 3 && reason.length <= 500 ? reason : null;
}

export async function handleCreateEnrollmentToken(
  request: Request,
  deps: {
    getSession: GetSession;
    createEnrollmentToken: (sessionToken: string, input: Record<string, unknown>) => Promise<unknown>;
  },
): Promise<Response> {
  if (!isSameOriginRequest(request)) return json({ error: "Token creation request was rejected." }, 403);
  const auth = await authorizeSession(deps.getSession, {
    minRole: "operator",
    signedOut: SIGNED_OUT,
    forbidden: "Your role cannot create enrollment tokens.",
  });
  if (auth instanceof Response) return auth;
  const input = tokenCreateInputFromUnknown(await readJsonBody(request));
  if (!input) return json({ error: "Token settings are invalid." }, 400);
  try {
    const token = createdTokenFromUnknown(await deps.createEnrollmentToken(auth.sessionToken, input));
    return token
      ? json(token, 201)
      : json({ error: "The management service returned an invalid token." }, 502);
  } catch (error) {
    const status = upstreamError(error)?.status;
    if (status === 400 || status === 409) return json({ error: "Token creation is unavailable." }, status);
    if (status === 403) return json({ error: "Your role cannot create this token." }, 403);
    if (status === 404) return json({ error: "The selected assignment no longer exists." }, 404);
    if (status === 422) return json({ error: "The token settings violate enrollment policy." }, 422);
    return json({ error: "Token creation is unavailable." }, 503);
  }
}

export async function handleRevokeEnrollmentToken(
  request: Request,
  tokenId: string,
  deps: {
    getSession: GetSession;
    revokeEnrollmentToken: (sessionToken: string, tokenId: string, reason: string) => Promise<unknown>;
  },
): Promise<Response> {
  if (!isSameOriginRequest(request)) return json({ error: "Revocation request was rejected." }, 403);
  const auth = await authorizeSession(deps.getSession, {
    minRole: "operator",
    signedOut: SIGNED_OUT,
    forbidden: "Your role cannot revoke tokens.",
  });
  if (auth instanceof Response) return auth;
  const reason = trustChangeReasonFromUnknown(await readJsonBody(request));
  if (!reason) return json({ error: "Enter a reason between 3 and 500 characters." }, 400);
  try {
    const result = await deps.revokeEnrollmentToken(auth.sessionToken, tokenId, reason);
    if (!isRecord(result) || typeof result.id !== "string" || typeof result.status !== "string") {
      return json({ error: "Token revocation is unavailable." }, 502);
    }
    return json({ id: result.id, status: result.status });
  } catch (error) {
    return upstreamError(error)?.status === 404
      ? json({ error: "The token no longer exists." }, 404)
      : json({ error: "Token revocation is unavailable." }, 503);
  }
}

export async function handleRevokeAgent(
  request: Request,
  agentId: string,
  deps: {
    getSession: GetSession;
    revokeAgent: (sessionToken: string, agentId: string, reason: string) => Promise<unknown>;
  },
): Promise<Response> {
  if (!isSameOriginRequest(request)) return json({ error: "Revocation request was rejected." }, 403);
  const auth = await authorizeSession(deps.getSession, {
    minRole: "admin",
    signedOut: SIGNED_OUT,
    forbidden: "Only an administrator can revoke agent credentials.",
  });
  if (auth instanceof Response) return auth;
  const reason = trustChangeReasonFromUnknown(await readJsonBody(request));
  if (!reason) return json({ error: "Enter a reason between 3 and 500 characters." }, 400);
  try {
    const result = await deps.revokeAgent(auth.sessionToken, agentId, reason);
    if (!isRecord(result) || typeof result.id !== "string" || typeof result.trust_state !== "string") {
      return json({ error: "Agent revocation is unavailable." }, 502);
    }
    return json({ id: result.id, trust_state: result.trust_state });
  } catch (error) {
    const status = upstreamError(error)?.status;
    if (status === 404) return json({ error: "The agent no longer exists." }, 404);
    if (status === 409) return json({ error: "The agent is already in that trust state." }, 409);
    return json({ error: "Agent revocation is unavailable." }, 503);
  }
}

// Proxies the personalized installer download (issue #9): mints nothing
// itself, just forwards the operator's session and streams the ZIP back. The
// bundled token rides only inside the archive body — never in the URL, the
// filename, or a log — and no upstream header is copied to the browser.
export async function handleInstallerPackage(
  request: Request,
  siteId: string,
  deps: {
    getSession: GetSession;
    requestInstallerPackage: (sessionToken: string, siteId: string) => Promise<Response>;
  },
): Promise<Response> {
  if (!isSameOriginRequest(request)) return json({ error: "Installer download request was rejected." }, 403);
  const auth = await authorizeSession(deps.getSession, {
    minRole: "operator",
    signedOut: SIGNED_OUT,
    forbidden: "Your role cannot download an installer.",
  });
  if (auth instanceof Response) return auth;

  let upstream: Response;
  try {
    upstream = await deps.requestInstallerPackage(auth.sessionToken, siteId);
  } catch {
    return json({ error: "The installer download is unavailable right now." }, 503);
  }
  if (!upstream.ok) {
    const body = await upstream.json().catch(() => null);
    const detail = isRecord(body) && isRecord(body.detail) ? body.detail : null;
    const code = detail && typeof detail.code === "string" ? detail.code : null;
    const { status, message } = installerDownloadError(upstream.status, code);
    return json({ error: message }, status);
  }

  const filename = installerDownloadFilename(upstream.headers.get("content-disposition"), siteId);
  return new Response(await upstream.arrayBuffer(), {
    status: 200,
    headers: {
      "Content-Type": "application/zip",
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Cache-Control": "no-store",
    },
  });
}
