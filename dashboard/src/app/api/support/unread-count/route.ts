// SPDX-License-Identifier: AGPL-3.0-only

import { getDashboardSession } from "@/lib/dashboard-session";
import { getSupportUnreadCount } from "@/lib/support";
import { handleUnreadCount } from "@/lib/support-route-core";

export const dynamic = "force-dynamic";

export function GET(request: Request) {
  return handleUnreadCount(request, {
    getSession: getDashboardSession,
    getSupportUnreadCount,
  });
}
