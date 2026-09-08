// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { handleReviewActivation } from "@/lib/admin-sessions-route-core";
import { applyAdminSessionResult } from "@/lib/admin-sessions-route";
import { reviewBreakGlassActivation } from "@/lib/nodelink-admin-sessions";

export const dynamic = "force-dynamic";

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ activationId: string }> },
) {
  const { activationId } = await context.params;
  return applyAdminSessionResult(
    await handleReviewActivation(request, activationId, {
      getSession: getDashboardSession,
      review: reviewBreakGlassActivation,
    }),
  );
}
