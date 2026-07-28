// SPDX-License-Identifier: AGPL-3.0-only

import { NextRequest, NextResponse } from "next/server";

import { isSameOrigin } from "@/lib/dashboard-auth-core";
import { getDashboardSession } from "@/lib/dashboard-session";
import { NodelinkApiError, nodelinkApiRequest } from "@/lib/nodelink-api";

export async function POST(request: NextRequest, context: { params: Promise<{ tokenId: string }> }) {
  if (!isSameOrigin(request.headers.get("origin"), request.nextUrl.origin)) {
    return NextResponse.json({ error: "Revocation request was rejected." }, { status: 403 });
  }
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") return NextResponse.json({ error: "Sign in again to continue." }, { status: 401 });
  if (session.operator.role === "readonly") return NextResponse.json({ error: "Your role cannot revoke tokens." }, { status: 403 });
  const { tokenId } = await context.params;
  const body = await request.json().catch(() => null);
  try {
    const result = await nodelinkApiRequest<Record<string, unknown>>(`/api/v1/enrollment-tokens/${encodeURIComponent(tokenId)}/revoke`, {
      body: JSON.stringify(body),
      headers: { "Content-Type": "application/json" },
      method: "POST",
      sessionToken: session.sessionToken,
    });
    return NextResponse.json(result);
  } catch (error) {
    const status = error instanceof NodelinkApiError && error.status === 404 ? 404 : 503;
    return NextResponse.json({ error: status === 404 ? "The token no longer exists." : "Token revocation is unavailable." }, { status });
  }
}
