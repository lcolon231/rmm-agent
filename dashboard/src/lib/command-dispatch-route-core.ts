// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Route core for typed command dispatch (issue #280).
 *
 * The service's floor for `POST /agents/{id}/commands` is readonly; whether a
 * given kind is allowed (script scope, admin-only power and remediation
 * actions) is decided per kind upstream, so this layer only revalidates the
 * session and turns refusal codes into operator-facing text.
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
import { validateDispatchInput, type DispatchInput } from "./command-console-core.ts";
import { isMaintenanceWindowErrorCode } from "./maintenance-windows-core.ts";

const DISPATCH_FAILED = "The command could not be dispatched. Try again.";

const forbiddenMessages: Record<string, string> = {
  script_execution_not_authorized:
    "PowerShell and shell execution require an explicit administrator-granted scope for this endpoint.",
  privileged_remediation_not_authorized:
    "Controlled file and registry remediation requires an administrator session.",
  power_operation_not_authorized:
    "Restart, shutdown, and power-action cancellation require an administrator session.",
  event_log_query_not_authorized: "Windows event log queries require an administrator session.",
};

const conflictMessages: Record<string, string> = {
  agent_not_trusted: "This endpoint is quarantined or revoked, so no new commands may be queued.",
  agent_capability_unsupported:
    "This endpoint must upgrade its agent before it can run this capability-gated operation.",
  power_operation_maintenance_window_required:
    "Start a maintenance window covering this endpoint before scheduling a restart or shutdown.",
  power_operation_delay_exceeds_maintenance_window:
    "Choose a shorter delay or extend the active maintenance window.",
  power_operation_user_consent_required:
    "A user is signed in. Confirm that user's consent or wait until the session ends.",
  patch_install_denied:
    "The patch approval policy denies or defers one or more selected updates. Choose approved updates only.",
  patch_install_no_approved_updates:
    "The patch approval policy approves none of this endpoint's currently missing updates.",
  patch_install_maintenance_window_required:
    "This endpoint's patch policy requires an active maintenance window before updates may install.",
};

export function dispatchErrorMessage(
  status: number,
  code: string | null,
): { message: string; status: number } {
  if (status === 401 || status === 403) {
    return {
      message: (code && forbiddenMessages[code]) ?? "Your operator session is not allowed to dispatch commands.",
      status: 403,
    };
  }
  if (status === 404) return { message: "This endpoint no longer exists.", status: 404 };
  if (status === 400 || status === 422) {
    return {
      message: "The server rejected this typed operation. Review every path, digest, type, and confirmation field.",
      status: 400,
    };
  }
  if (status === 409) {
    return {
      message: (code && conflictMessages[code])
        ?? "This endpoint's agent does not support a compatible signed command format.",
      status: 409,
    };
  }
  if (status === 429) {
    return {
      message: "This endpoint's command queue is full. Wait for pending commands to finish or expire.",
      status: 429,
    };
  }
  return { message: DISPATCH_FAILED, status: 502 };
}

export async function handleDispatchCommand(
  request: Request,
  endpointId: string,
  deps: {
    getSession: GetSession;
    dispatchCommand: (sessionToken: string, endpointId: string, input: DispatchInput) => Promise<unknown>;
  },
): Promise<Response> {
  if (!isSameOriginRequest(request)) return json({ error: "Dispatch request was rejected." }, 403);
  const auth = await authorizeSession(deps.getSession, {
    minRole: "readonly",
    signedOut: "Sign in to dispatch commands.",
    forbidden: "Your operator session is not allowed to dispatch commands.",
  });
  if (auth instanceof Response) return auth;

  const body = await readJsonBody(request);
  if (body === undefined) return json({ error: "The dispatch request was malformed." }, 400);
  const input = validateDispatchInput(body);
  if (!input) {
    return json({ error: "Provide a supported command kind, valid typed inputs, and a valid expiry." }, 400);
  }

  try {
    const result = await deps.dispatchCommand(auth.sessionToken, endpointId, input);
    if (!isRecord(result) || typeof result.id !== "string" || typeof result.status !== "string") {
      return json({ error: DISPATCH_FAILED }, 502);
    }
    return json({ command: { id: result.id, status: result.status } });
  } catch (error) {
    const upstream = upstreamError(error);
    if (!upstream) return json({ error: DISPATCH_FAILED }, 502);
    const { message, status } = dispatchErrorMessage(upstream.status, upstream.code);
    // Only codes the console can turn into a link reach the browser; anything
    // else stays a message so no unrouted code leaks.
    const code = isMaintenanceWindowErrorCode(upstream.code) ? upstream.code : null;
    return json({ error: message, ...(code ? { code } : {}) }, status);
  }
}
