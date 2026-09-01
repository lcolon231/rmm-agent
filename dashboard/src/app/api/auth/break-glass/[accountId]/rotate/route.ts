// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { handleRotateBreakGlass } from "@/lib/admin-sessions-route-core";
import { applyAdminSessionResult } from "@/lib/admin-sessions-route";
import { rotateBreakGlassCredential } from "@/lib/nodelink-admin-sessions";

export const dynamic = "force-dynamic";

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ accountId: string }> },
) {
  const { accountId } = await context.params;
  return applyAdminSessionResult(
    await handleRotateBreakGlass(request, accountId, {
      getSession: getDashboardSession,
      rotate: rotateBreakGlassCredential,
    }),
  );
}
