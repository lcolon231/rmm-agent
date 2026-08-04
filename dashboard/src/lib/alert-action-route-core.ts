// SPDX-License-Identifier: AGPL-3.0-only

import { isSameOrigin, requestOrigin } from "./dashboard-auth-core.ts";
import {
  monitoringAlertDetailFromUnknown,
  validateAlertActionInput,
  type AlertActionInput,
  type MonitoringAlertDetail,
} from "./monitoring-core.ts";

type RouteSession =
  | { kind: "anonymous" }
  | { kind: "unavailable" }
  | { kind: "authenticated"; operator: { role: "readonly" | "operator" | "admin" }; sessionToken: string };

type AlertAction = "acknowledge" | "assign" | "comments" | "resolve";

function json(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

function upstreamStatus(error: unknown): { status: number; code: string | null } | null {
  if (!error || typeof error !== "object") return null;
  const record = error as Record<string, unknown>;
  return typeof record.status === "number"
    ? { status: record.status, code: typeof record.code === "string" ? record.code : null }
    : null;
}

function actionError(error: unknown): Response {
  const upstream = upstreamStatus(error);
  if (upstream?.status === 409) {
    return json({ error: upstream.code === "alert_version_conflict"
      ? "This alert changed while you were working. Refresh and try again."
      : "That action is not valid for the alert's current state." }, 409);
  }
  if (upstream?.status === 404) return json({ error: "This alert no longer exists." }, 404);
  if (upstream?.status === 422) return json({ error: "The selected assignee is unavailable." }, 422);
  if (upstream?.status === 401) return json({ error: "Your session expired. Sign in again." }, 401);
  if (upstream?.status === 403) return json({ error: "Your role cannot update alerts." }, 403);
  return json({ error: "The alert update could not be confirmed. Try again." }, 503);
}

export async function handleAlertAction(
  request: Request,
  alertId: string,
  action: AlertAction,
  dependencies: {
    getSession: () => Promise<RouteSession>;
    performAction: (
      sessionToken: string, alertId: string, action: AlertAction, input: AlertActionInput,
    ) => Promise<unknown>;
  },
): Promise<Response> {
  if (!isSameOrigin(
    request.headers.get("origin"),
    requestOrigin(request.url, request.headers.get("host")),
  )) return json({ error: "The alert update request was rejected." }, 403);

  const session = await dependencies.getSession().catch(() => ({ kind: "unavailable" } as const));
  if (session.kind === "anonymous") return json({ error: "Your session expired. Sign in again." }, 401);
  if (session.kind === "unavailable") return json({ error: "Session verification is unavailable." }, 503);
  if (session.operator.role === "readonly") return json({ error: "Your role cannot update alerts." }, 403);

  const input = validateAlertActionInput(await request.json().catch(() => null));
  if (!input || ((action === "comments" || action === "resolve") && !input.comment)) {
    return json({ error: "Check the alert version and enter a comment of 2,000 characters or fewer." }, 400);
  }
  try {
    const alert = monitoringAlertDetailFromUnknown(
      await dependencies.performAction(session.sessionToken, alertId, action, input),
    );
    return alert ? json({ alert }) : json({ error: "The service returned an invalid alert." }, 502);
  } catch (error) {
    return actionError(error);
  }
}

export type { MonitoringAlertDetail };
