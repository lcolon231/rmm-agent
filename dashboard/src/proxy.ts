// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

import { sanitizedLoginUrl } from "@/lib/dashboard-auth-core";

export function proxy(request: NextRequest) {
  const sanitized = sanitizedLoginUrl(request.nextUrl);
  return sanitized ? NextResponse.redirect(sanitized) : NextResponse.next();
}

export const config = {
  matcher: "/login",
};
