// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { handleListSessions } from "@/lib/admin-sessions-route-core";
import { applyAdminSessionResult } from "@/lib/admin-sessions-route";
import { listOwnSessions } from "@/lib/nodelink-admin-sessions";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  return applyAdminSessionResult(
    await handleListSessions(request, {
      getSession: getDashboardSession,
      list: listOwnSessions,
    }),
  );
}
