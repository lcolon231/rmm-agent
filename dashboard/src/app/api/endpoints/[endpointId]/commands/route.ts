// SPDX-License-Identifier: AGPL-3.0-only

import { NextRequest, NextResponse } from "next/server";

import { validateDispatchInput } from "@/lib/command-console-core";
import { dispatchCommand } from "@/lib/command-console";
import { isSameOrigin, sessionCookieName } from "@/lib/dashboard-auth-core";
import { NodelinkApiError } from "@/lib/nodelink-api";

export const dynamic = "force-dynamic";

function dispatchErrorMessage(error: NodelinkApiError): { message: string; status: number } {
  if (error.status === 401 || error.status === 403) {
    return {
      message: "Your operator session is not allowed to dispatch commands.",
      status: 403,
    };
  }
  if (error.status === 404) {
    return { message: "This endpoint no longer exists.", status: 404 };
  }
  if (error.status === 409) {
    return {
      message:
        error.code === "agent_not_trusted"
          ? "This endpoint is quarantined or revoked, so no new commands may be queued."
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
  if (!isSameOrigin(request.headers.get("origin"), request.nextUrl.origin)) {
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
      { error: "Provide a supported command kind, a script within limits, and a valid expiry." },
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
