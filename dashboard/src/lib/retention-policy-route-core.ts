// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Authenticated proxy for a tenant's retention policy (issue #311).
 *
 * The browser never talks to the management service directly. Reads pass for
 * any signed-in operator (the server decides visibility); writes need a
 * same-origin request, the global `admin` role mirroring the service's
 * `require_role(admin)`, and a body restricted to the #88 fields. The server's
 * `detail.code` and `category` pass through so the editor can map a 409, 422 or
 * `step_up_required` to the right control. Server-side RBAC, step-up and
 * validation remain the authority; nothing here can widen them.
 */

import { isSameOrigin, requestOrigin } from "./dashboard-auth-core.ts";
import {
  RETENTION_CATEGORY_NAMES,
  retentionErrorMessage,
  retentionPolicyFromUnknown,
} from "./retention-policy-core.ts";

type Role = "readonly" | "operator" | "admin";
type RouteSession =
  | { kind: "anonymous" }
  | { kind: "unavailable" }
  | { kind: "authenticated"; operator: { role: Role }; sessionToken: string };

export type RetentionMethod = "GET" | "PUT" | "DELETE";

export type RetentionRouteDependencies = {
  getSession: () => Promise<RouteSession>;
  send: (token: string, method: RetentionMethod, clientId: string, body?: unknown) => Promise<Response>;
};

const CATEGORY_KEYS: readonly string[] = RETENTION_CATEGORY_NAMES;

function json(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

function failure(status: number, error: string, code: string | null = null, category: string | null = null) {
  return json({ error, code, category }, status);
}

function isVersion(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

/** The exact body to forward, or `null` if it is not a well-formed #88 write. */
function writeBody(method: "PUT" | "DELETE", body: unknown): Record<string, unknown> | null {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  const raw = body as Record<string, unknown>;
  if (!isVersion(raw.expected_version)) return null;
  const allowed = method === "PUT" ? CATEGORY_KEYS : [];
  const forwarded: Record<string, unknown> = { expected_version: raw.expected_version };
  for (const [key, value] of Object.entries(raw)) {
    if (key === "expected_version") continue;
    if (!allowed.includes(key) || (value !== null && !isVersion(value))) return null;
    forwarded[key] = value;
  }
  return forwarded;
}

async function relay(response: Response): Promise<Response> {
  const body = await response.json().catch(() => null) as Record<string, unknown> | null;
  if (response.ok) {
    const policy = retentionPolicyFromUnknown(body);
    return policy
      ? json({ policy })
      : failure(502, "The service returned an invalid retention policy.");
  }
  const detail = body && typeof body.detail === "object" && body.detail !== null
    ? body.detail as Record<string, unknown> : {};
  const code = typeof detail.code === "string" ? detail.code : null;
  const category = typeof detail.category === "string" && CATEGORY_KEYS.includes(detail.category)
    ? detail.category : null;
  const status = response.status;
  if (status === 401) return failure(401, "Your session expired. Sign in again.");
  const known = retentionErrorMessage(code);
  if (status === 403) {
    return failure(403, known ?? "Your role cannot change retention for this client.", code);
  }
  if (status === 404 || status === 409 || status === 422) {
    return failure(status, known ?? "The management service rejected this retention policy.", code, category);
  }
  return failure(503, "The retention policy change could not be confirmed. Try again.");
}

export async function handleRetentionPolicyRequest(
  request: Request,
  clientId: string,
  dependencies: RetentionRouteDependencies,
): Promise<Response> {
  const method = request.method.toUpperCase() as RetentionMethod;
  const writing = method === "PUT" || method === "DELETE";
  if (writing && !isSameOrigin(
    request.headers.get("origin"),
    requestOrigin(request.url, request.headers.get("host")),
  )) return failure(403, "The retention policy request was rejected.");
  const session = await dependencies.getSession().catch(() => ({ kind: "unavailable" } as const));
  if (session.kind === "anonymous") return failure(401, "Your session expired. Sign in again.");
  if (session.kind === "unavailable") return failure(503, "Session verification is unavailable.");
  if (!clientId.trim() || clientId.length > 36) {
    return failure(404, retentionErrorMessage("client_not_found") ?? "", "client_not_found");
  }
  if (writing && session.operator.role !== "admin") {
    return failure(403, "Your role cannot change retention for this client.");
  }
  let body: Record<string, unknown> | undefined;
  if (method === "PUT" || method === "DELETE") {
    const parsed = writeBody(method, await request.json().catch(() => null));
    if (!parsed) return failure(400, "The retention policy request is malformed.");
    body = parsed;
  }
  try {
    return await relay(await dependencies.send(session.sessionToken, method, clientId, body));
  } catch {
    return failure(503, "The retention policy change could not be confirmed. Try again.");
  }
}
