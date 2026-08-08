// SPDX-License-Identifier: AGPL-3.0-only

import { NextResponse } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { nodelinkApiRequest } from "@/lib/nodelink-api";

export async function POST(
  _request: Request,
  { params }: { params: Promise<{ scheduleId: string }> },
) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") {
    return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  }

  const { scheduleId } = await params;
  try {
    const data = await nodelinkApiRequest<unknown>(`/api/v1/scheduled-tasks/${scheduleId}/run-now`, {
      method: "POST",
      sessionToken: session.sessionToken,
    });
    return NextResponse.json(data);
  } catch (error: any) {
    return NextResponse.json(
      { error: error?.message || "Failed to run scheduled task." },
      { status: error?.status || 500 },
    );
  }
}
