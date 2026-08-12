// SPDX-License-Identifier: AGPL-3.0-only

import { NextRequest, NextResponse } from "next/server";

import { isSameOrigin, requestOrigin, sessionCookieName } from "@/lib/dashboard-auth-core";
import { NodelinkApiError } from "@/lib/nodelink-api";
import { sendShellInput } from "@/lib/shell-session";

export const dynamic = "force-dynamic";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ endpointId: string; sessionId: string }> },
) {
  if (!isSameOrigin(request.headers.get("origin"), requestOrigin(request.url, request.headers.get("host")))) {
    return NextResponse.json({ error: "Shell input was rejected." }, { status: 403 });
  }
  const sessionToken = request.cookies.get(sessionCookieName())?.value;
  if (!sessionToken) return NextResponse.json({ error: "Sign in to use the shell." }, { status: 401 });
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Shell input is invalid." }, { status: 400 }); }
  if (typeof body !== "object" || body === null) return NextResponse.json({ error: "Shell input is invalid." }, { status: 400 });
  const candidate = body as Record<string, unknown>;
  if (!Number.isSafeInteger(candidate.seq) || Number(candidate.seq) < 1 || typeof candidate.data_b64 !== "string" || candidate.data_b64.length > 24_000) {
    return NextResponse.json({ error: "Shell input is invalid." }, { status: 400 });
  }
  const { endpointId, sessionId } = await params;
  try {
    const session = await sendShellInput(sessionToken, endpointId, sessionId, { seq: Number(candidate.seq), data_b64: candidate.data_b64 });
    return NextResponse.json({ session });
  } catch (error) {
    const status = error instanceof NodelinkApiError ? error.status : 502;
    return NextResponse.json({ error: status === 429 ? "The endpoint is catching up. Try again." : "Shell input could not be sent." }, { status });
  }
}
