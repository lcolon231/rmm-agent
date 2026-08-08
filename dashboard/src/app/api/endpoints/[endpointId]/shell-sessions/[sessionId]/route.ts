// SPDX-License-Identifier: AGPL-3.0-only

import { NextRequest, NextResponse } from "next/server";

import { isSameOrigin, requestOrigin, sessionCookieName } from "@/lib/dashboard-auth-core";
import { NodelinkApiError } from "@/lib/nodelink-api";
import { closeShellSession, getShellSession } from "@/lib/shell-session";

export const dynamic = "force-dynamic";

function authorize(request: NextRequest, requireSameOrigin: boolean):
  | { ok: true; sessionToken: string }
  | { ok: false; response: NextResponse } {
  if (
    requireSameOrigin &&
    !isSameOrigin(
      request.headers.get("origin"),
      requestOrigin(request.url, request.headers.get("host")),
    )
  ) {
    return {
      ok: false,
      response: NextResponse.json(
        { error: "Shell session request was rejected." },
        { status: 403 },
      ),
    };
  }
  const sessionToken = request.cookies.get(sessionCookieName())?.value;
  if (!sessionToken) {
    return {
      ok: false,
      response: NextResponse.json(
        { error: "Sign in to manage shell sessions." },
        { status: 401 },
      ),
    };
  }
  return { ok: true, sessionToken };
}

function mapError(error: unknown): NextResponse {
  if (error instanceof NodelinkApiError) {
    const status = error.status === 401 ? 401 : error.status === 404 ? 404 : 403;
    return NextResponse.json(
      { error: "The shell session is not available." },
      { status },
    );
  }
  return NextResponse.json(
    { error: "The shell session could not be reached. Try again." },
    { status: 502 },
  );
}

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ endpointId: string; sessionId: string }> },
) {
  const auth = authorize(request, false);
  if (!auth.ok) {
    return auth.response;
  }
  const { endpointId, sessionId } = await params;
  try {
    const session = await getShellSession(auth.sessionToken, endpointId, sessionId);
    return NextResponse.json({ session });
  } catch (error) {
    return mapError(error);
  }
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ endpointId: string; sessionId: string }> },
) {
  const auth = authorize(request, true);
  if (!auth.ok) {
    return auth.response;
  }
  const { endpointId, sessionId } = await params;
  try {
    const session = await closeShellSession(auth.sessionToken, endpointId, sessionId);
    return NextResponse.json({ session });
  } catch (error) {
    return mapError(error);
  }
}
