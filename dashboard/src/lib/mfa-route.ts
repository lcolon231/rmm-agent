// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import { NextResponse } from "next/server";

import type { MfaRouteResult } from "@/lib/mfa-route-core";

/**
 * Apply a handler result's cookie instructions to its response.
 *
 * The pure handlers in `mfa-route-core.ts` return cookies as data so they stay
 * testable without a Next runtime; this is the one place that turns those
 * instructions into actual `Set-Cookie` headers.
 */
export function applyMfaResult(result: MfaRouteResult): Response {
  if (result.cookies.length === 0) {
    return result.response;
  }
  const response = new NextResponse(result.response.body, {
    status: result.response.status,
    headers: result.response.headers,
  });
  for (const cookie of result.cookies) {
    response.cookies.set(cookie.name, cookie.value, cookie.options);
  }
  return response;
}
