// SPDX-License-Identifier: AGPL-3.0-only

import { isSameOrigin, requestOrigin } from "./dashboard-auth-core.ts";
import {
  alertWebhookDeliveryFromUnknown,
  webhookEndpointFromUnknown,
  webhookEndpointSecretFromUnknown,
  webhookValidationFromUnknown,
  type WebhookEventType,
} from "./monitoring-core.ts";

type Role = "readonly" | "operator" | "admin";
type RouteSession =
  | { kind: "anonymous" }
  | { kind: "unavailable" }
  | { kind: "authenticated"; operator: { role: Role }; sessionToken: string };
type SessionDependency = () => Promise<RouteSession>;
type WebhookEndpointUpdateInput = {
  request_id: string;
  expected_version: number;
  name?: string;
  url?: string;
  event_types?: WebhookEventType[];
  enabled?: boolean;
};

const eventTypes = new Set<WebhookEventType>([
  "opened", "reopened", "acknowledged", "manual_resolution",
  "automatic_recovery", "policy_revised", "policy_deleted", "policy_superseded",
]);

function json(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

function errorStatus(error: unknown): number {
  return error && typeof error === "object"
    && typeof (error as { status?: unknown }).status === "number"
    ? (error as { status: number }).status : 503;
}

function mappedError(error: unknown, noun: string): Response {
  const status = errorStatus(error);
  if (status === 401) return json({ error: "Your session expired. Sign in again." }, 401);
  if (status === 403) return json({ error: `Your role cannot manage ${noun}.` }, 403);
  if (status === 404) return json({ error: `This ${noun} no longer exists.` }, 404);
  if (status === 409) return json({ error: `This ${noun} changed. Refresh and try again.` }, 409);
  if (status === 422) return json({ error: "The destination is not a supported public HTTPS endpoint." }, 422);
  return json({ error: `The ${noun} change could not be confirmed. Try again.` }, 503);
}

async function authorize(
  request: Request,
  getSession: SessionDependency,
  minimumRole: "operator" | "admin",
): Promise<Response | { sessionToken: string }> {
  if (!isSameOrigin(
    request.headers.get("origin"),
    requestOrigin(request.url, request.headers.get("host")),
  )) return json({ error: "The webhook request was rejected." }, 403);
  const session = await getSession().catch(() => ({ kind: "unavailable" } as const));
  if (session.kind === "anonymous") return json({ error: "Your session expired. Sign in again." }, 401);
  if (session.kind === "unavailable") return json({ error: "Session verification is unavailable." }, 503);
  const allowed = minimumRole === "admin"
    ? session.operator.role === "admin"
    : session.operator.role !== "readonly";
  return allowed
    ? { sessionToken: session.sessionToken }
    : json({ error: "Your role cannot manage webhooks." }, 403);
}

function isResponse(value: Response | { sessionToken: string }): value is Response {
  return value instanceof Response;
}

function validRequestId(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{16,64}$/.test(value);
}

function validEventTypes(value: unknown): value is WebhookEventType[] {
  return Array.isArray(value) && value.length >= 1 && value.length <= 8
    && new Set(value).size === value.length
    && value.every((item) => eventTypes.has(item as WebhookEventType));
}

export async function handleWebhookEndpointCreate(
  request: Request,
  dependencies: {
    getSession: SessionDependency;
    createEndpoint: (
      token: string,
      input: { name: string; url: string; event_types: WebhookEventType[] },
    ) => Promise<unknown>;
  },
): Promise<Response> {
  const authorized = await authorize(request, dependencies.getSession, "admin");
  if (isResponse(authorized)) return authorized;
  const body = await request.json().catch(() => null) as Record<string, unknown> | null;
  if (!body || Object.keys(body).some((key) => !["name", "url", "event_types"].includes(key))
      || typeof body.name !== "string" || body.name.trim().length < 1
      || body.name.trim().length > 200 || typeof body.url !== "string"
      || body.url.trim().length < 1 || body.url.trim().length > 2048
      || !validEventTypes(body.event_types)) {
    return json({ error: "Name, public HTTPS URL, and at least one event are required." }, 400);
  }
  try {
    const endpoint = webhookEndpointSecretFromUnknown(await dependencies.createEndpoint(
      authorized.sessionToken,
      { name: body.name.trim(), url: body.url.trim(), event_types: body.event_types },
    ));
    return endpoint
      ? json({ endpoint }, 201)
      : json({ error: "The service returned an invalid endpoint." }, 502);
  } catch (error) {
    return mappedError(error, "webhook endpoint");
  }
}

export async function handleWebhookEndpointUpdate(
  request: Request,
  endpointId: string,
  dependencies: {
    getSession: SessionDependency;
    updateEndpoint: (token: string, endpointId: string, input: WebhookEndpointUpdateInput) => Promise<unknown>;
  },
): Promise<Response> {
  const authorized = await authorize(request, dependencies.getSession, "admin");
  if (isResponse(authorized)) return authorized;
  const body = await request.json().catch(() => null) as Record<string, unknown> | null;
  const allowedKeys = new Set([
    "request_id", "expected_version", "name", "url", "event_types", "enabled",
  ]);
  if (!body || Object.keys(body).some((key) => !allowedKeys.has(key))
      || !validRequestId(body.request_id) || !Number.isInteger(body.expected_version)
      || (body.expected_version as number) < 1
      || !(body.name === undefined || (typeof body.name === "string"
        && body.name.trim().length >= 1 && body.name.trim().length <= 200))
      || !(body.url === undefined || (typeof body.url === "string"
        && body.url.trim().length >= 1 && body.url.trim().length <= 2048))
      || !(body.event_types === undefined || validEventTypes(body.event_types))
      || !(body.enabled === undefined || typeof body.enabled === "boolean")
      || ["name", "url", "event_types", "enabled"].every((key) => body[key] === undefined)) {
    return json({ error: "The endpoint change is invalid." }, 400);
  }
  const input: WebhookEndpointUpdateInput = {
    request_id: body.request_id as string,
    expected_version: body.expected_version as number,
    ...(typeof body.name === "string" ? { name: body.name.trim() } : {}),
    ...(typeof body.url === "string" ? { url: body.url.trim() } : {}),
    ...(validEventTypes(body.event_types) ? { event_types: body.event_types } : {}),
    ...(typeof body.enabled === "boolean" ? { enabled: body.enabled } : {}),
  };
  try {
    const endpoint = webhookEndpointFromUnknown(
      await dependencies.updateEndpoint(authorized.sessionToken, endpointId, input),
    );
    return endpoint
      ? json({ endpoint })
      : json({ error: "The service returned an invalid endpoint." }, 502);
  } catch (error) {
    return mappedError(error, "webhook endpoint");
  }
}

export async function handleWebhookEndpointValidate(
  request: Request,
  endpointId: string,
  dependencies: {
    getSession: SessionDependency;
    validateEndpoint: (token: string, endpointId: string) => Promise<unknown>;
  },
): Promise<Response> {
  const authorized = await authorize(request, dependencies.getSession, "operator");
  if (isResponse(authorized)) return authorized;
  try {
    const validation = webhookValidationFromUnknown(
      await dependencies.validateEndpoint(authorized.sessionToken, endpointId),
    );
    return validation
      ? json({ validation })
      : json({ error: "The service returned invalid validation evidence." }, 502);
  } catch (error) {
    return mappedError(error, "webhook endpoint");
  }
}

export async function handleWebhookSecretRotate(
  request: Request,
  endpointId: string,
  dependencies: {
    getSession: SessionDependency;
    rotateSecret: (token: string, endpointId: string, requestId: string, version: number) => Promise<unknown>;
  },
): Promise<Response> {
  const authorized = await authorize(request, dependencies.getSession, "admin");
  if (isResponse(authorized)) return authorized;
  const body = await request.json().catch(() => null) as Record<string, unknown> | null;
  if (!body || !validRequestId(body.request_id)
      || !Number.isInteger(body.expected_version) || (body.expected_version as number) < 1) {
    return json({ error: "The rotation request is invalid." }, 400);
  }
  try {
    const endpoint = webhookEndpointSecretFromUnknown(await dependencies.rotateSecret(
      authorized.sessionToken, endpointId, body.request_id, body.expected_version as number,
    ));
    return endpoint
      ? json({ endpoint })
      : json({ error: "The service returned an invalid rotated secret." }, 502);
  } catch (error) {
    return mappedError(error, "webhook endpoint");
  }
}

export async function handleWebhookEndpointDelete(
  request: Request,
  endpointId: string,
  dependencies: {
    getSession: SessionDependency;
    deleteEndpoint: (token: string, endpointId: string, requestId: string, version: number) => Promise<unknown>;
  },
): Promise<Response> {
  const authorized = await authorize(request, dependencies.getSession, "admin");
  if (isResponse(authorized)) return authorized;
  const body = await request.json().catch(() => null) as Record<string, unknown> | null;
  if (!body || !validRequestId(body.request_id)
      || !Number.isInteger(body.expected_version) || (body.expected_version as number) < 1) {
    return json({ error: "The deletion request is invalid." }, 400);
  }
  try {
    await dependencies.deleteEndpoint(
      authorized.sessionToken, endpointId, body.request_id, body.expected_version as number,
    );
    return json({ deleted: true });
  } catch (error) {
    return mappedError(error, "webhook endpoint");
  }
}

export async function handleWebhookDeliveryRetry(
  request: Request,
  deliveryId: string,
  dependencies: {
    getSession: SessionDependency;
    retryDelivery: (token: string, deliveryId: string, requestId: string) => Promise<unknown>;
  },
): Promise<Response> {
  const authorized = await authorize(request, dependencies.getSession, "operator");
  if (isResponse(authorized)) return authorized;
  const body = await request.json().catch(() => null) as Record<string, unknown> | null;
  if (!body || !validRequestId(body.request_id)) {
    return json({ error: "The retry request is invalid." }, 400);
  }
  try {
    const delivery = alertWebhookDeliveryFromUnknown(await dependencies.retryDelivery(
      authorized.sessionToken, deliveryId, body.request_id,
    ));
    return delivery
      ? json({ delivery })
      : json({ error: "The service returned an invalid delivery." }, 502);
  } catch (error) {
    return mappedError(error, "webhook delivery");
  }
}
