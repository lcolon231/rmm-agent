// SPDX-License-Identifier: AGPL-3.0-only
import type { NextRequest } from "next/server";
import { handleOverrideAction } from "@/lib/emergency-override-route-core";
import { getDashboardSession } from "@/lib/dashboard-session";
import {
  activateEmergencyOverride,
  reviewEmergencyOverride,
  revokeEmergencyOverride,
  runEmergencyOverride,
} from "@/lib/emergency-overrides";

export const dynamic = "force-dynamic";

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ overrideId: string }> },
) {
  const { overrideId } = await context.params;
  return handleOverrideAction(request, "review", overrideId, {
    getSession: getDashboardSession,
    activate: activateEmergencyOverride,
    revoke: revokeEmergencyOverride,
    review: reviewEmergencyOverride,
    run: runEmergencyOverride,
  });
}
