// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { handleRevokeOtherSessions } from "@/lib/admin-sessions-route-core";
import { applyAdminSessionResult } from "@/lib/admin-sessions-route";
import { revokeOtherOwnSessions } from "@/lib/nodelink-admin-sessions";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  return applyAdminSessionResult(
    await handleRevokeOtherSessions(request, {
      getSession: getDashboardSession,
      revokeOthers: revokeOtherOwnSessions,
    }),
  );
}
