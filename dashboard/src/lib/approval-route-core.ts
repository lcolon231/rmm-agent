// SPDX-License-Identifier: AGPL-3.0-only

/** Authenticated proxy handler for approval decisions (issue #64).
 *
 * The dashboard never exposes the management service to the browser, so a
 * verdict passes through here: same-origin check, session cookie exchanged for
 * the server-held token, a role floor mirroring the service's own
 * `require_role(operator)`, and full re-validation of the reason.
 *
 * Nothing here can widen the control. Self-approval, distinct-identity
 * counting, approver eligibility, expiry, and single-use consumption are all
 * decided server side; this layer only turns the service's refusal codes into
 * something a reviewer can read.
 */

import { isSameOrigin, requestOrigin } from "./dashboard-auth-core.ts";
import {
  approvalRequestDetailFromUnknown,
  isValidDecisionReason,
  type ApprovalRequestDetail,
} from "./approvals-core.ts";

type Role = "readonly" | "operator" | "admin";
type RouteSession =
  | { kind: "anonymous" }
  | { kind: "unavailable" }
  | { kind: "authenticated"; operator: { role: Role }; sessionToken: string };

export type ApprovalAction = "approve" | "reject" | "cancel";

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

/** Refusal codes, phrased for the person who just clicked. */
const MESSAGES: Record<string, string> = {
  approval_self_not_permitted: "You raised this request, so you cannot approve it.",
  approval_already_recorded: "You have already recorded a decision on this request.",
  approval_request_expired: "This request expired. Raise a new one.",
  approval_request_not_pending: "This request has already been decided or withdrawn.",
  approval_request_already_approved: "This request already has the approvals it needs.",
  approver_disabled: "Your account cannot approve requests.",
  approver_tenant_not_visible: "You do not have access to this request's client.",
  approver_client_role_insufficient: "Your role for this client cannot approve requests.",
  approver_script_permission_missing:
    "You cannot approve a command you are not permitted to run yourself.",
  approver_script_permission_scope_mismatch:
    "You cannot approve a command you are not permitted to run on this endpoint.",
  approver_administrator_role_required:
    "You cannot approve a command you are not permitted to run yourself.",
  approver_operator_role_insufficient:
    "You cannot approve a command you are not permitted to run yourself.",
};

function mappedError(error: unknown): Response {
  const { status, code } = upstream(error);
  if (status === 401) return json({ error: "Your session expired. Sign in again." }, 401);
  if (status === 404) return json({ error: "This request no longer exists." }, 404);
  if (code && MESSAGES[code]) return json({ error: MESSAGES[code] }, status);
  if (status === 403) return json({ error: "You are not eligible to decide this request." }, 403);
  if (status === 409) return json({ error: "That action is not valid for this request." }, 409);
  if (status === 422) return json({ error: "The management service rejected this reason." }, 422);
  return json({ error: "The decision could not be confirmed. Try again." }, 503);
}

export async function handleApprovalAction(
  request: Request,
  requestId: string,
  action: ApprovalAction,
  dependencies: {
    getSession: () => Promise<RouteSession>;
    performAction: (
      sessionToken: string,
      requestId: string,
      action: ApprovalAction,
      reason: string,
    ) => Promise<unknown>;
  },
): Promise<Response> {
  if (
    !isSameOrigin(
      request.headers.get("origin"),
      requestOrigin(request.url, request.headers.get("host")),
    )
  ) {
    return json({ error: "The approval request was rejected." }, 403);
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
    return json({ error: "Your role cannot decide approval requests." }, 403);
  }

  const body = (await request.json().catch(() => null)) as unknown;
  const reason =
    body && typeof body === "object" && typeof (body as { reason?: unknown }).reason === "string"
      ? (body as { reason: string }).reason
      : null;
  if (reason === null || !isValidDecisionReason(reason)) {
    return json(
      { error: "Enter a printable reason of 10 to 512 characters." },
      400,
    );
  }

  try {
    const detail = approvalRequestDetailFromUnknown(
      await dependencies.performAction(session.sessionToken, requestId, action, reason.trim()),
    );
    return detail
      ? json({ request: detail })
      : json({ error: "The service returned an invalid approval request." }, 502);
  } catch (error) {
    return mappedError(error);
  }
}

export type { ApprovalRequestDetail };
