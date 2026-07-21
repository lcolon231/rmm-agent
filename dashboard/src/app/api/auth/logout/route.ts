import { NextRequest, NextResponse } from "next/server";

import {
  isSameOrigin,
  sessionCookieName,
  sessionCookieOptions,
} from "@/lib/dashboard-auth-core";
import { revokeOperatorTokens } from "@/lib/nodelink-auth";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  if (!isSameOrigin(request.headers.get("origin"), request.nextUrl.origin)) {
    return NextResponse.json({ error: "Sign-out request was rejected." }, { status: 403 });
  }

  const sessionToken = request.cookies.get(sessionCookieName())?.value;
  let revoked = true;
  if (sessionToken) {
    try {
      await revokeOperatorTokens(sessionToken);
    } catch {
      revoked = false;
    }
  }

  const response = NextResponse.json(
    revoked ? { status: "signed_out" } : { error: "Signed out locally; token revocation was unavailable." },
    { status: revoked ? 200 : 503 },
  );
  response.cookies.set(sessionCookieName(), "", { ...sessionCookieOptions(), maxAge: 0 });
  return response;
}
