// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import { NextResponse } from "next/server";

import type { AdminSessionRouteResult } from "@/lib/admin-sessions-route-core";

/**
 * Turn a handler result's cookie instructions into real `Set-Cookie` headers.
 *
 * The pure handlers return cookies as data so they stay testable without a Next
 * runtime; this is the only place that applies them.
 */
export function applyAdminSessionResult(result: AdminSessionRouteResult): Response {
  if (result.cookies.length === 0) return result.response;
  const response = new NextResponse(result.response.body, {
    status: result.response.status,
    headers: result.response.headers,
  });
  for (const cookie of result.cookies) {
    response.cookies.set(cookie.name, cookie.value, cookie.options);
  }
  return response;
}
