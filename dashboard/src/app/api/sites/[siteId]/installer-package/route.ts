// SPDX-License-Identifier: AGPL-3.0-only

import { NextRequest, NextResponse } from "next/server";

import { isSameOrigin, requestOrigin } from "@/lib/dashboard-auth-core";
import { getDashboardSession } from "@/lib/dashboard-session";
import { canManageEnrollment } from "@/lib/enrollment-core";
import {
  installerDownloadError,
  installerDownloadFilename,
} from "@/lib/installer-download-core";
import { extractNodelinkErrorCode, nodelinkApiRequestRaw } from "@/lib/nodelink-api";

export const dynamic = "force-dynamic";

// Proxies the personalized installer download (issue #9): mints nothing itself,
// just forwards the operator's server session to the management API and streams
// the ZIP back. The bundled token rides only inside the archive body — it is
// never placed in the URL, the filename, or a log by this route.
export async function POST(
  request: NextRequest,
  context: { params: Promise<{ siteId: string }> },
) {
  if (
    !isSameOrigin(
      request.headers.get("origin"),
      requestOrigin(request.url, request.headers.get("host")),
    )
  ) {
    return NextResponse.json(
      { error: "Installer download request was rejected." },
      { status: 403 },
    );
  }
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") {
    return NextResponse.json({ error: "Sign in again to continue." }, { status: 401 });
  }
  if (!canManageEnrollment(session.operator.role)) {
    return NextResponse.json(
      { error: "Your role cannot download an installer." },
      { status: 403 },
    );
  }

  const { siteId } = await context.params;
  let upstream: Response;
  try {
    upstream = await nodelinkApiRequestRaw(
      `/api/v1/sites/${encodeURIComponent(siteId)}/installer-package`,
      { method: "POST", sessionToken: session.sessionToken },
    );
  } catch {
    return NextResponse.json(
      { error: "The installer download is unavailable right now." },
      { status: 503 },
    );
  }

  if (!upstream.ok) {
    const body = await upstream.json().catch(() => null);
    const { status, message } = installerDownloadError(
      upstream.status,
      extractNodelinkErrorCode(body),
    );
    return NextResponse.json({ error: message }, { status });
  }

  const bytes = await upstream.arrayBuffer();
  const filename = installerDownloadFilename(
    upstream.headers.get("content-disposition"),
    siteId,
  );
  return new NextResponse(bytes, {
    status: 200,
    headers: {
      "Content-Type": "application/zip",
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Cache-Control": "no-store",
    },
  });
}
