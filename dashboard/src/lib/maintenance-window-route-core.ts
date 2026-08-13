// SPDX-License-Identifier: AGPL-3.0-only

/** Authenticated proxy handlers for maintenance windows (issue #211).
 *
 * The dashboard never exposes the management service to the browser, so window
 * creation and deletion pass through here: same-origin check, session cookie
 * exchanged for the server-held token, role floor mirroring the service's own
 * `require_role(operator)`, and a full re-validation of the request. Server-side
 * RBAC and audit logging remain the authority; nothing here can widen them.
 */

import { isSameOrigin, requestOrigin } from "./dashboard-auth-core.ts";
import {
  maintenanceWindowFromUnknown,
  validateMaintenanceWindowRequest,
  type MaintenanceWindowCreateRequest,
} from "./maintenance-windows-core.ts";

type Role = "readonly" | "operator" | "admin";
type RouteSession =
  | { kind: "anonymous" }
  | { kind: "unavailable" }
  | { kind: "authenticated"; operator: { role: Role }; sessionToken: string };
type SessionDependency = () => Promise<RouteSession>;

function json(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

function errorStatus(error: unknown): number {
  return error && typeof error === "object"
    && typeof (error as { status?: unknown }).status === "number"
    ? (error as { status: number }).status : 503;
}

function mappedError(error: unknown): Response {
  const status = errorStatus(error);
  const code = error && typeof error === "object"
    ? (error as { code?: unknown }).code : null;
  if (status === 401) return json({ error: "Your session expired. Sign in again." }, 401);
  if (status === 403) return json({ error: "Your role cannot manage maintenance windows." }, 403);
  if (status === 404) {
    return json({
      error: code === "monitoring_scope_target_not_found"
        ? "That client, site, or endpoint no longer exists."
        : "This maintenance window no longer exists.",
    }, 404);
  }
  if (status === 409) {
    return json({
      error: code === "maintenance_window_limit_reached"
        ? "The maintenance window limit is reached. Delete a closed window first."
        : "This maintenance window changed. Refresh and try again.",
    }, 409);
  }
  if (status === 422) return json({ error: "The management service rejected this window." }, 422);
  return json({ error: "The maintenance window change could not be confirmed. Try again." }, 503);
}

async function authorize(
  request: Request,
  getSession: SessionDependency,
): Promise<Response | { sessionToken: string }> {
  if (!isSameOrigin(
    request.headers.get("origin"),
    requestOrigin(request.url, request.headers.get("host")),
  )) return json({ error: "The maintenance window request was rejected." }, 403);
  const session = await getSession().catch(() => ({ kind: "unavailable" } as const));
  if (session.kind === "anonymous") return json({ error: "Your session expired. Sign in again." }, 401);
  if (session.kind === "unavailable") return json({ error: "Session verification is unavailable." }, 503);
  return session.operator.role === "readonly"
    ? json({ error: "Your role cannot manage maintenance windows." }, 403)
    : { sessionToken: session.sessionToken };
}

function isResponse(value: Response | { sessionToken: string }): value is Response {
  return value instanceof Response;
}

export async function handleMaintenanceWindowCreate(
  request: Request,
  dependencies: {
    getSession: SessionDependency;
    createWindow: (token: string, input: MaintenanceWindowCreateRequest) => Promise<unknown>;
    now?: () => number;
  },
): Promise<Response> {
  const authorized = await authorize(request, dependencies.getSession);
  if (isResponse(authorized)) return authorized;
  const body = await request.json().catch(() => null) as unknown;
  const validated = validateMaintenanceWindowRequest(body, (dependencies.now ?? Date.now)());
  if (!validated.ok) return json({ error: validated.error }, 400);
  try {
    const window = maintenanceWindowFromUnknown(
      await dependencies.createWindow(authorized.sessionToken, validated.request),
    );
    return window
      ? json({ window }, 201)
      : json({ error: "The service returned an invalid maintenance window." }, 502);
  } catch (error) {
    return mappedError(error);
  }
}

export async function handleMaintenanceWindowDelete(
  request: Request,
  windowId: string,
  dependencies: {
    getSession: SessionDependency;
    listWindows: (token: string) => Promise<{ id: string; name: string }[]>;
    deleteWindow: (token: string, windowId: string) => Promise<unknown>;
  },
): Promise<Response> {
  const authorized = await authorize(request, dependencies.getSession);
  if (isResponse(authorized)) return authorized;
  const body = await request.json().catch(() => null) as Record<string, unknown> | null;
  const confirmName = body && typeof body.confirm_name === "string" ? body.confirm_name.trim() : "";
  if (!body || Object.keys(body).some((key) => key !== "confirm_name") || !confirmName) {
    return json({ error: "Type the window name to confirm ending it." }, 400);
  }
  if (!windowId.trim() || windowId.length > 36) {
    return json({ error: "This maintenance window no longer exists." }, 404);
  }
  try {
    // Ending a window can revoke authorization for an in-flight power action,
    // so the typed name is matched against the live record, not just echoed.
    const windows = await dependencies.listWindows(authorized.sessionToken);
    const target = windows.find((window) => window.id === windowId);
    if (!target) return json({ error: "This maintenance window no longer exists." }, 404);
    if (target.name !== confirmName) {
      return json({ error: "The typed name does not match this window. Refresh and try again." }, 409);
    }
    await dependencies.deleteWindow(authorized.sessionToken, windowId);
    return json({ deleted: true });
  } catch (error) {
    return mappedError(error);
  }
}
