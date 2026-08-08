// SPDX-License-Identifier: AGPL-3.0-only

import { NextResponse } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { nodelinkApiRequest } from "@/lib/nodelink-api";

export async function POST(request: Request) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") {
    return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON request body." }, { status: 400 });
  }

  try {
    const data = await nodelinkApiRequest<unknown>("/api/v1/scheduled-tasks", {
      method: "POST",
      sessionToken: session.sessionToken,
      body: JSON.stringify(body),
    });
    return NextResponse.json(data, { status: 201 });
  } catch (error: unknown) {
    const err = error as { message?: string; status?: number };
    return NextResponse.json(
      { error: err?.message || "Failed to create scheduled task." },
      { status: err?.status || 500 },
    );
  }
}
