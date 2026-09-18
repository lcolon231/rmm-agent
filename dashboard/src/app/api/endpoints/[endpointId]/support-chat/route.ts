// SPDX-License-Identifier: AGPL-3.0-only

import { NextRequest, NextResponse } from "next/server";

import { isSameOrigin, requestOrigin, sessionCookieName } from "@/lib/dashboard-auth-core";
import { NodelinkApiError, nodelinkApiRequest } from "@/lib/nodelink-api";

export const dynamic = "force-dynamic";

function messageFor(code: string | null, status: number): string {
  if (code === "support_chat_unsupported") return "This endpoint must be updated before a technician can start support chat.";
  if (code === "support_chat_agent_untrusted") return "Support chat is unavailable while this endpoint is not trusted.";
  if (code === "support_chat_not_configured") return "Support chat is not configured on the server.";
  if (status === 404) return "The endpoint was not found or is outside your client access.";
  if (status === 403) return "Your role cannot start support chat for this endpoint.";
  return "NodeLink Support could not be started. Try again.";
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ endpointId: string }> },
) {
  if (!isSameOrigin(request.headers.get("origin"), requestOrigin(request.url, request.headers.get("host")))) {
    return NextResponse.json({ error: "Support chat request was rejected." }, { status: 403 });
  }
  const sessionToken = request.cookies.get(sessionCookieName())?.value;
  if (!sessionToken) {
    return NextResponse.json({ error: "Sign in to start support chat." }, { status: 401 });
  }
  const { endpointId } = await params;
  try {
    const conversation = await nodelinkApiRequest<{ conversation_id: string }>(
      "/api/v1/support/conversations",
      {
        method: "POST",
        sessionToken,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent_id: endpointId }),
      },
    );
    return NextResponse.json({ conversation_id: conversation.conversation_id }, { status: 201 });
  } catch (error) {
    if (error instanceof NodelinkApiError) {
      return NextResponse.json(
        { error: messageFor(error.code, error.status) },
        { status: error.status >= 400 && error.status < 600 ? error.status : 502 },
      );
    }
    return NextResponse.json({ error: "NodeLink Support could not be started. Try again." }, { status: 502 });
  }
}
