// SPDX-License-Identifier: AGPL-3.0-only

import { NextRequest, NextResponse } from "next/server";

import { isSameOrigin, requestOrigin } from "@/lib/dashboard-auth-core";
import { getDashboardSession } from "@/lib/dashboard-session";
import { NodelinkApiError, nodelinkApiRequest } from "@/lib/nodelink-api";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  if (!isSameOrigin(
    request.headers.get("origin"),
    requestOrigin(request.url, request.headers.get("host")),
  )) {
    return NextResponse.json({ error: "Token creation request was rejected." }, { status: 403 });
  }
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") {
    return NextResponse.json({ error: "Sign in again to continue." }, { status: 401 });
  }
  if (session.operator.role === "readonly") {
    return NextResponse.json({ error: "Your role cannot create enrollment tokens." }, { status: 403 });
  }
  const body = await request.json().catch(() => null);
  if (!body || typeof body !== "object") {
    return NextResponse.json({ error: "Token settings are invalid." }, { status: 400 });
  }
  try {
    const token = await nodelinkApiRequest<Record<string, unknown>>("/api/v1/enrollment-tokens", {
      body: JSON.stringify(body),
      headers: { "Content-Type": "application/json" },
      method: "POST",
      sessionToken: session.sessionToken,
    });
    return NextResponse.json(token, { status: 201 });
  } catch (error) {
    const status = error instanceof NodelinkApiError && [400, 403, 404, 409, 422].includes(error.status) ? error.status : 503;
    return NextResponse.json({ error: status === 403 ? "Your role cannot create this token." : status === 404 ? "The selected assignment no longer exists." : status === 422 ? "The token settings violate enrollment policy." : "Token creation is unavailable." }, { status });
  }
}
