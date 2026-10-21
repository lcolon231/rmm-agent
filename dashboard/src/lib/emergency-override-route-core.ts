// SPDX-License-Identifier: AGPL-3.0-only

/** Authenticated proxy handler for emergency overrides (issue #65).
 *
 * Same shape as the approval proxy: same-origin check, session cookie
 * exchanged for the server-held token, a role floor mirroring the service's
 * `require_role(operator)`, and full re-validation of every text field.
 *
 * Nothing here can widen the control. Policy opt-in, tenant-admin standing,
 * command authorization, step-up, expiry, single use, and who may review are
 * all decided by the management service; this layer only turns its refusal
 * codes into something the operator can read.
 */

import { isSameOrigin, requestOrigin } from "./dashboard-auth-core.ts";
import {
  OVERRIDE_COMMAND_KINDS,
  OVERRIDE_MESSAGES,
  emergencyOverrideDetailFromUnknown,
  isValidJustification,
  isValidNote,
  isValidTtlSeconds,
  type EmergencyOverrideDetail,
} from "./emergency-overrides-core.ts";

type Role = "readonly" | "operator" | "admin";
type RouteSession =
  | { kind: "anonymous" }
  | { kind: "unavailable" }
  | { kind: "authenticated"; operator: { role: Role }; sessionToken: string };

export type OverrideAction = "activate" | "revoke" | "review" | "run";

export type ActivateInput = {
  agent_id: string;
  kind: string;
  payload: Record<string, unknown>;
  justification: string;
  ttl_seconds?: number;
};

export type OverrideRouteDependencies = {
  getSession: () => Promise<RouteSession>;
  activate: (sessionToken: string, input: ActivateInput) => Promise<unknown>;
  revoke: (sessionToken: string, overrideId: string, reason: string) => Promise<unknown>;
  review: (sessionToken: string, overrideId: string, note: string) => Promise<unknown>;
  /** Dispatch the bound command citing the override; resolves to the detail. */
  run: (sessionToken: string, overrideId: string) => Promise<unknown>;
};

function json(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

function upstream(error: unknown): { status: number; code: string | null } {
  if (!error || typeof error !== "object") return { status: 503, code: null };
  const record = error as Record<string, unknown>;
  return {
    status: typeof record.status === "number" ? record.status : 503,
    code: typeof record.code === "string" ? record.code : null,
  };
}

function mappedError(error: unknown, action: OverrideAction): Response {
  const { status, code } = upstream(error);
  if (code && OVERRIDE_MESSAGES[code]) return json({ error: OVERRIDE_MESSAGES[code] }, status);
  if (status === 401) return json({ error: "Your session expired. Sign in again." }, 401);
  if (status === 404) return json({ error: "This override or endpoint no longer exists." }, 404);
  if (status === 403) {
    return json(
      {
        error:
          action === "run"
            ? "You are not permitted to dispatch this command."
            : "You are not permitted to do that.",
      },
      403,
    );
  }
  if (status === 409) return json({ error: "That action is not valid for this override." }, 409);
  if (status === 422 || status === 400) {
    return json({ error: "The management service rejected the request." }, 422);
  }
  if (status === 429) return json({ error: OVERRIDE_MESSAGES.emergency_override_limit_reached }, 429);
  return json({ error: "The override could not be processed. Try again." }, 503);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

/** Validate an activation body. Returns null on any shape problem. */
export function parseActivateInput(body: unknown): ActivateInput | null {
  if (!isRecord(body)) return null;
  const { agent_id: agentId, kind, payload, justification, ttl_seconds: ttl } = body;
  if (typeof agentId !== "string" || !agentId || agentId.length > 36) return null;
  if (typeof kind !== "string" || !(OVERRIDE_COMMAND_KINDS as readonly string[]).includes(kind)) {
    return null;
  }
  if (payload !== undefined && !isRecord(payload)) return null;
  if (typeof justification !== "string" || !isValidJustification(justification)) return null;
  if (ttl !== undefined && ttl !== null && !isValidTtlSeconds(ttl)) return null;
  return {
    agent_id: agentId,
    kind,
    payload: payload ?? {},
    justification: justification.trim(),
    ...(isValidTtlSeconds(ttl) ? { ttl_seconds: ttl } : {}),
  };
}

export async function handleOverrideAction(
  request: Request,
  action: OverrideAction,
  overrideId: string | null,
  dependencies: OverrideRouteDependencies,
): Promise<Response> {
  if (
    !isSameOrigin(
      request.headers.get("origin"),
      requestOrigin(request.url, request.headers.get("host")),
    )
  ) {
    return json({ error: "The request was rejected." }, 403);
  }

  const session = await dependencies
    .getSession()
    .catch(() => ({ kind: "unavailable" }) as const);
  if (session.kind === "anonymous") {
    return json({ error: "Your session expired. Sign in again." }, 401);
  }
  if (session.kind === "unavailable") {
    return json({ error: "Session verification is unavailable." }, 503);
  }
  if (session.operator.role === "readonly") {
    return json({ error: "Your role cannot act on emergency overrides." }, 403);
  }

  const body = action === "run" ? null : ((await request.json().catch(() => null)) as unknown);

  try {
    let result: unknown;
    if (action === "activate") {
      const input = parseActivateInput(body);
      if (!input) {
        return json(
          {
            error:
              "Provide an endpoint, a supported command kind, a JSON object payload, and a printable justification of 20 to 512 characters.",
          },
          400,
        );
      }
      result = await dependencies.activate(session.sessionToken, input);
    } else {
      if (!overrideId) return json({ error: "Override id is required." }, 400);
      if (action === "run") {
        result = await dependencies.run(session.sessionToken, overrideId);
      } else {
        const field = action === "revoke" ? "reason" : "note";
        const text =
          isRecord(body) && typeof body[field] === "string" ? (body[field] as string) : null;
        if (text === null || !isValidNote(text)) {
          return json({ error: `Enter a printable ${field} of 10 to 512 characters.` }, 400);
        }
        result =
          action === "revoke"
            ? await dependencies.revoke(session.sessionToken, overrideId, text.trim())
            : await dependencies.review(session.sessionToken, overrideId, text.trim());
      }
    }
    const detail = emergencyOverrideDetailFromUnknown(result);
    return detail
      ? json({ override: detail }, action === "activate" ? 201 : 200)
      : json({ error: "The service returned an invalid override." }, 502);
  } catch (error) {
    return mappedError(error, action);
  }
}

export type { EmergencyOverrideDetail };
