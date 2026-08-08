// SPDX-License-Identifier: AGPL-3.0-only

import { NextRequest, NextResponse } from "next/server";

import { isSameOrigin, requestOrigin, sessionCookieName } from "@/lib/dashboard-auth-core";
import { NodelinkApiError } from "@/lib/nodelink-api";
import { openShellSession } from "@/lib/shell-session";
import { shellSessionOpenErrorMessage } from "@/lib/shell-session-core";

export const dynamic = "force-dynamic";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ endpointId: string }> },
) {
  if (
    !isSameOrigin(
      request.headers.get("origin"),
      requestOrigin(request.url, request.headers.get("host")),
    )
  ) {
    return NextResponse.json(
      { error: "Shell session request was rejected." },
      { status: 403 },
    );
  }

  const sessionToken = request.cookies.get(sessionCookieName())?.value;
  if (!sessionToken) {
    return NextResponse.json(
      { error: "Sign in to open a shell session." },
      { status: 401 },
    );
  }

  const { endpointId } = await params;
  try {
    const session = await openShellSession(sessionToken, endpointId);
    return NextResponse.json({ session }, { status: 201 });
  } catch (error) {
    if (error instanceof NodelinkApiError) {
      const message = shellSessionOpenErrorMessage(error.code, error.status);
      const status = error.status === 401 ? 401 : error.status === 404 ? 404 : 403;
      return NextResponse.json({ error: message }, { status });
    }
    return NextResponse.json(
      { error: "The shell session could not be opened. Try again." },
      { status: 502 },
    );
  }
}
