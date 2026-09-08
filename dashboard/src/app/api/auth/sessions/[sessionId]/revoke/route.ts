// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { handleRevokeSession } from "@/lib/admin-sessions-route-core";
import { applyAdminSessionResult } from "@/lib/admin-sessions-route";
import { revokeOwnSession } from "@/lib/nodelink-admin-sessions";

export const dynamic = "force-dynamic";

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ sessionId: string }> },
) {
  const { sessionId } = await context.params;
  return applyAdminSessionResult(
    await handleRevokeSession(request, sessionId, {
      getSession: getDashboardSession,
      revoke: revokeOwnSession,
    }),
  );
}
