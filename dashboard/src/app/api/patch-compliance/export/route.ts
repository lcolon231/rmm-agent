// SPDX-License-Identifier: AGPL-3.0-only

import { NextRequest, NextResponse } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { nodelinkApiRequestRaw } from "@/lib/nodelink-api";
import type { ComplianceState } from "@/lib/patch-compliance-core";

export const dynamic = "force-dynamic";

const states = new Set<ComplianceState>([
  "compliant",
  "non_compliant",
  "stale",
  "unknown",
  "exempt",
]);

export async function GET(request: NextRequest) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") {
    return NextResponse.json({ error: "Sign in again to continue." }, { status: 401 });
  }

  const incoming = request.nextUrl.searchParams;
  const format = incoming.get("format") ?? "csv";
  const state = incoming.get("state");
  if (
    !["csv", "json"].includes(format)
    || (state !== null && !states.has(state as ComplianceState))
  ) {
    return NextResponse.json({ error: "The export request is invalid." }, { status: 400 });
  }

  const query = new URLSearchParams({ format });
  for (const field of ["client_id", "site_id"] as const) {
    const value = incoming.get(field);
    if (value) query.set(field, value.slice(0, 36));
  }
  if (state) query.set("state", state);

  let upstream: Response;
  try {
    upstream = await nodelinkApiRequestRaw(`/api/v1/patch-compliance/export?${query}`, {
      method: "GET",
      sessionToken: session.sessionToken,
    });
  } catch {
    return NextResponse.json(
      { error: "The patch compliance export is unavailable right now." },
      { status: 503 },
    );
  }
  if (!upstream.ok) {
    const status = upstream.status >= 400 && upstream.status < 600 ? upstream.status : 502;
    return NextResponse.json({ error: "The patch compliance export failed." }, { status });
  }

  const disposition = upstream.headers.get("content-disposition") ?? "";
  const filenameMatch = /filename="([A-Za-z0-9._-]+)"/.exec(disposition);
  const filename = filenameMatch?.[1] ?? `patch-compliance.${format}`;
  return new NextResponse(await upstream.arrayBuffer(), {
    status: 200,
    headers: {
      "Content-Type": format === "csv" ? "text/csv; charset=utf-8" : "application/json",
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Cache-Control": "no-store",
    },
  });
}
