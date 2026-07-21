// SPDX-License-Identifier: AGPL-3.0-only

import { NextRequest, NextResponse } from "next/server";

import {
  isSameOrigin,
  sessionCookieName,
  sessionCookieOptions,
  validateLoginCredentials,
} from "@/lib/dashboard-auth-core";
import { NodelinkAuthenticationError, authenticateOperator } from "@/lib/nodelink-auth";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  if (!isSameOrigin(request.headers.get("origin"), request.nextUrl.origin)) {
    return NextResponse.json({ error: "Sign-in request was rejected." }, { status: 403 });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Enter your email and password." }, { status: 400 });
  }

  const credentials = validateLoginCredentials(body);
  if (!credentials) {
    return NextResponse.json({ error: "Enter a valid email and password." }, { status: 400 });
  }

  try {
    const { operator, sessionToken } = await authenticateOperator(credentials);
    const response = NextResponse.json({ operator });
    response.cookies.set(sessionCookieName(), sessionToken, sessionCookieOptions());
    return response;
  } catch (error) {
    if (error instanceof NodelinkAuthenticationError) {
      const status = error.status === 429 ? 429 : error.status === 401 ? 401 : 503;
      const message = status === 401
        ? "Email or password is incorrect."
        : status === 429
          ? "Too many sign-in attempts. Try again later."
          : "Sign-in is unavailable. Try again later.";
      return NextResponse.json({ error: message }, { status });
    }

    return NextResponse.json({ error: "Sign-in is unavailable. Try again later." }, { status: 503 });
  }
}
