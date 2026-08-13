// SPDX-License-Identifier: AGPL-3.0-only

import { NextRequest, NextResponse } from "next/server";

import { isSameOrigin, requestOrigin, sessionCookieName } from "@/lib/dashboard-auth-core";
import { NodelinkApiError } from "@/lib/nodelink-api";
import { launchRemoteDesktop } from "@/lib/remote-desktop";
import { remoteDesktopLaunchErrorMessage } from "@/lib/remote-desktop-core";

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
      { error: "Remote desktop request was rejected." },
      { status: 403 },
    );
  }

  const sessionToken = request.cookies.get(sessionCookieName())?.value;
  if (!sessionToken) {
    return NextResponse.json(
      { error: "Sign in to launch a remote desktop session." },
      { status: 401 },
    );
  }

  const { endpointId } = await params;
  try {
    const launch = await launchRemoteDesktop(sessionToken, endpointId);
    return NextResponse.json({ launch }, { status: 201 });
  } catch (error) {
    if (error instanceof NodelinkApiError) {
      const message = remoteDesktopLaunchErrorMessage(error.code, error.status);
      const status =
        error.status === 401
          ? 401
          : error.status === 404
            ? 404
            : error.status === 503
              ? 503
              : error.status === 429
                ? 429
                : error.status === 409
                  ? 409
                  : 403;
      return NextResponse.json({ error: message }, { status });
    }
    return NextResponse.json(
      { error: "The remote desktop session could not be launched. Try again." },
      { status: 502 },
    );
  }
}
