// SPDX-License-Identifier: AGPL-3.0-only

import { NextRequest, NextResponse } from "next/server";

import { sessionCookieName } from "@/lib/dashboard-auth-core";
import { NodelinkApiError } from "@/lib/nodelink-api";
import { getRemoteDesktopAvailability } from "@/lib/remote-desktop";

export const dynamic = "force-dynamic";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ endpointId: string }> },
) {
  const sessionToken = request.cookies.get(sessionCookieName())?.value;
  if (!sessionToken) {
    return NextResponse.json(
      { error: "Sign in to view remote desktop availability." },
      { status: 401 },
    );
  }

  const { endpointId } = await params;
  try {
    const availability = await getRemoteDesktopAvailability(
      sessionToken,
      endpointId,
    );
    return NextResponse.json({ availability }, { status: 200 });
  } catch (error) {
    if (error instanceof NodelinkApiError) {
      const status = error.status === 401 ? 401 : error.status === 404 ? 404 : 502;
      return NextResponse.json(
        { error: "Remote desktop availability is unavailable." },
        { status },
      );
    }
    return NextResponse.json(
      { error: "Remote desktop availability is unavailable." },
      { status: 502 },
    );
  }
}
