// SPDX-License-Identifier: AGPL-3.0-only

import { getDashboardSession } from "@/lib/dashboard-session";
import { fetchBreakGlassActivations } from "@/lib/nodelink-admin-sessions";

export const dynamic = "force-dynamic";

/**
 * The activation history and review queue.
 *
 * GET only and scoped by the upstream's platform-admin check, so it needs no
 * origin guard: there is no state change to forge, and a caller sees nothing
 * the API would not already show them.
 */
export async function GET() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") {
    return Response.json(
      { error: "Sign in to view break-glass activations." },
      { status: 401, headers: { "Cache-Control": "no-store" } },
    );
  }
  const activations = await fetchBreakGlassActivations(session.sessionToken);
  if (!activations) {
    return Response.json(
      { error: "Break-glass activations are unavailable, or your role cannot see them." },
      { status: 503, headers: { "Cache-Control": "no-store" } },
    );
  }
  return Response.json(activations, { headers: { "Cache-Control": "no-store" } });
}
