// SPDX-License-Identifier: AGPL-3.0-only

import { handleBreakGlassActivations } from "@/lib/auth-route-core";
import { getDashboardSession } from "@/lib/dashboard-session";
import { fetchBreakGlassActivations } from "@/lib/nodelink-admin-sessions";

export const dynamic = "force-dynamic";

export function GET(request: Request) {
  return handleBreakGlassActivations(request, {
    fetchBreakGlassActivations,
    getSession: getDashboardSession,
  });
}
