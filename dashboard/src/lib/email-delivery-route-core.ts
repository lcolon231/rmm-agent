// SPDX-License-Identifier: AGPL-3.0-only

import { isSameOrigin, requestOrigin } from "./dashboard-auth-core.ts";
import {
  alertEmailDeliveryFromUnknown,
  type AlertEmailDelivery,
} from "./monitoring-core.ts";

type RouteSession =
  | { kind: "anonymous" }
  | { kind: "unavailable" }
  | { kind: "authenticated"; operator: { role: "readonly" | "operator" | "admin" }; sessionToken: string };

function json(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

export async function handleEmailDeliveryRetry(
  request: Request,
  deliveryId: string,
  dependencies: {
    getSession: () => Promise<RouteSession>;
    retryDelivery: (sessionToken: string, deliveryId: string, requestId: string) => Promise<unknown>;
  },
): Promise<Response> {
  if (!isSameOrigin(
    request.headers.get("origin"),
    requestOrigin(request.url, request.headers.get("host")),
  )) return json({ error: "The retry request was rejected." }, 403);

  const session = await dependencies.getSession().catch(() => ({ kind: "unavailable" } as const));
  if (session.kind === "anonymous") return json({ error: "Your session expired. Sign in again." }, 401);
  if (session.kind === "unavailable") return json({ error: "Session verification is unavailable." }, 503);
  if (session.operator.role === "readonly") return json({ error: "Your role cannot retry deliveries." }, 403);
  const body = await request.json().catch(() => null) as { request_id?: unknown } | null;
  if (!body || typeof body.request_id !== "string"
      || !/^[A-Za-z0-9_-]{16,64}$/.test(body.request_id)) {
    return json({ error: "The retry request is invalid." }, 400);
  }
  try {
    const delivery = alertEmailDeliveryFromUnknown(
      await dependencies.retryDelivery(
        session.sessionToken, deliveryId, body.request_id,
      ),
    );
    return delivery
      ? json({ delivery })
      : json({ error: "The service returned an invalid delivery." }, 502);
  } catch (error) {
    const status = error && typeof error === "object"
      && typeof (error as { status?: unknown }).status === "number"
      ? (error as { status: number }).status : 503;
    if (status === 404) return json({ error: "This delivery no longer exists." }, 404);
    if (status === 409) return json({ error: "This delivery is no longer eligible for retry." }, 409);
    if (status === 401) return json({ error: "Your session expired. Sign in again." }, 401);
    if (status === 403) return json({ error: "Your role cannot retry deliveries." }, 403);
    return json({ error: "The retry could not be confirmed. Try again." }, 503);
  }
}

export type { AlertEmailDelivery };
