// SPDX-License-Identifier: AGPL-3.0-only

import { NextRequest, NextResponse } from "next/server";

import { isSameOrigin, requestOrigin } from "@/lib/dashboard-auth-core";
import { getDashboardSession } from "@/lib/dashboard-session";
import { NodelinkApiError, nodelinkApiRequest } from "@/lib/nodelink-api";

export async function POST(request: NextRequest, context: { params: Promise<{ agentId: string }> }) {
  if (!isSameOrigin(
    request.headers.get("origin"),
    requestOrigin(request.url, request.headers.get("host")),
  )) {
    return NextResponse.json({ error: "Revocation request was rejected." }, { status: 403 });
  }
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") return NextResponse.json({ error: "Sign in again to continue." }, { status: 401 });
  if (session.operator.role !== "admin") return NextResponse.json({ error: "Only an administrator can revoke agent credentials." }, { status: 403 });
  const { agentId } = await context.params;
  const body = await request.json().catch(() => null);
  try {
    const result = await nodelinkApiRequest<Record<string, unknown>>(`/api/v1/agents/${encodeURIComponent(agentId)}/revoke`, {
      body: JSON.stringify(body),
      headers: { "Content-Type": "application/json" },
      method: "POST",
      sessionToken: session.sessionToken,
    });
    return NextResponse.json(result);
  } catch (error) {
    const status = error instanceof NodelinkApiError && [404, 409].includes(error.status) ? error.status : 503;
    return NextResponse.json({ error: status === 404 ? "The agent no longer exists." : status === 409 ? "The agent is already in that trust state." : "Agent revocation is unavailable." }, { status });
  }
}
