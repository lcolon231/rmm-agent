// SPDX-License-Identifier: AGPL-3.0-only

import { getDashboardSession } from "@/lib/dashboard-session";
import { getSupportConversations } from "@/lib/support";
import { handleListConversations } from "@/lib/support-route-core";

export const dynamic = "force-dynamic";

export function GET(request: Request) {
  return handleListConversations(request, {
    getSession: getDashboardSession,
    getSupportConversations,
  });
}
