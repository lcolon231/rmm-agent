// SPDX-License-Identifier: AGPL-3.0-only

import { NextRequest, NextResponse } from "next/server";

import { validateDispatchInput } from "@/lib/command-console-core";
import { dispatchCommand } from "@/lib/command-console";
import { isSameOrigin, requestOrigin, sessionCookieName } from "@/lib/dashboard-auth-core";
import { NodelinkApiError } from "@/lib/nodelink-api";

export const dynamic = "force-dynamic";

function dispatchErrorMessage(error: NodelinkApiError): { message: string; status: number } {
  if (error.status === 401 || error.status === 403) {
    return {
      message:
        error.code === "script_execution_not_authorized"
          ? "PowerShell and shell execution require an explicit administrator-granted scope for this endpoint."
          : error.code === "privileged_remediation_not_authorized"
            ? "Controlled file and registry remediation requires an administrator session."
          : error.code === "power_operation_not_authorized"
            ? "Restart, shutdown, and power-action cancellation require an administrator session."
          : "Your operator session is not allowed to dispatch commands.",
      status: 403,
    };
  }
  if (error.status === 404) {
    return { message: "This endpoint no longer exists.", status: 404 };
  }
  if (error.status === 400 || error.status === 422) {
    return { message: "The server rejected this typed operation. Review every path, digest, type, and confirmation field.", status: 400 };
  }
  if (error.status === 409) {
    return {
      message:
        error.code === "agent_not_trusted"
          ? "This endpoint is quarantined or revoked, so no new commands may be queued."
          : error.code === "agent_capability_unsupported"
            ? "This endpoint must upgrade its agent before it can run this capability-gated operation."
          : error.code === "power_operation_maintenance_window_required"
            ? "Start a maintenance window covering this endpoint before scheduling a restart or shutdown."
          : error.code === "power_operation_delay_exceeds_maintenance_window"
            ? "Choose a shorter delay or extend the active maintenance window."
          : error.code === "power_operation_user_consent_required"
            ? "A user is signed in. Confirm that user's consent or wait until the session ends."
          : "This endpoint's agent does not support a compatible signed command format.",
      status: 409,
    };
  }
  if (error.status === 429) {
    return {
      message: "This endpoint's command queue is full. Wait for pending commands to finish or expire.",
      status: 429,
    };
  }
  return { message: "The command could not be dispatched. Try again.", status: 502 };
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ endpointId: string }> },
) {
  if (!isSameOrigin(
    request.headers.get("origin"),
    requestOrigin(request.url, request.headers.get("host")),
  )) {
    return NextResponse.json({ error: "Dispatch request was rejected." }, { status: 403 });
  }

  const sessionToken = request.cookies.get(sessionCookieName())?.value;
  if (!sessionToken) {
    return NextResponse.json({ error: "Sign in to dispatch commands." }, { status: 401 });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "The dispatch request was malformed." }, { status: 400 });
  }

  const input = validateDispatchInput(body);
  if (!input) {
    return NextResponse.json(
      { error: "Provide a supported command kind, valid typed inputs, and a valid expiry." },
      { status: 400 },
    );
  }

  const { endpointId } = await params;
  try {
    const command = await dispatchCommand(sessionToken, endpointId, input);
    return NextResponse.json({ command });
  } catch (error) {
    if (error instanceof NodelinkApiError) {
      const { message, status } = dispatchErrorMessage(error);
      return NextResponse.json({ error: message }, { status });
    }
    return NextResponse.json(
      { error: "The command could not be dispatched. Try again." },
      { status: 502 },
    );
  }
}
