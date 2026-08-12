// SPDX-License-Identifier: AGPL-3.0-only

import { NextRequest, NextResponse } from "next/server";

import { sessionCookieName } from "@/lib/dashboard-auth-core";
import { NodelinkApiError } from "@/lib/nodelink-api";
import { readShellOutput } from "@/lib/shell-session";

export const dynamic = "force-dynamic";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ endpointId: string; sessionId: string }> },
) {
  const sessionToken = request.cookies.get(sessionCookieName())?.value;
  if (!sessionToken) return NextResponse.json({ error: "Sign in to use the shell." }, { status: 401 });
  const after = Number(request.nextUrl.searchParams.get("after") ?? "0");
  const ack = Number(request.nextUrl.searchParams.get("ack") ?? "0");
  if (!Number.isSafeInteger(after) || after < 0 || !Number.isSafeInteger(ack) || ack < 0) {
    return NextResponse.json({ error: "Shell cursor is invalid." }, { status: 400 });
  }
  const { endpointId, sessionId } = await params;
  try {
    return NextResponse.json(await readShellOutput(sessionToken, endpointId, sessionId, after, ack));
  } catch (error) {
    const status = error instanceof NodelinkApiError ? error.status : 502;
    return NextResponse.json({ error: status === 409 ? "The live output window expired. Reopen the shell." : "Live output could not be reached." }, { status });
  }
}
