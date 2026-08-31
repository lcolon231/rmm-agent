// SPDX-License-Identifier: AGPL-3.0-only

import { getDashboardSession } from "@/lib/dashboard-session";
import { fetchMfaStatus } from "@/lib/nodelink-mfa";

export const dynamic = "force-dynamic";

/**
 * Read-only MFA state for the signed-in operator.
 *
 * GET, and scoped entirely to the caller's own session, so it needs no
 * origin check: there is no state change to forge and nothing here that the
 * caller is not already entitled to see.
 */
export async function GET() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") {
    return Response.json(
      { error: "Sign in to view your security settings." },
      { status: 401, headers: { "Cache-Control": "no-store" } },
    );
  }
  const status = await fetchMfaStatus(session.sessionToken);
  if (!status) {
    return Response.json(
      { error: "Your multi-factor state is unavailable. Try again." },
      { status: 503, headers: { "Cache-Control": "no-store" } },
    );
  }
  return Response.json(status, { headers: { "Cache-Control": "no-store" } });
}
