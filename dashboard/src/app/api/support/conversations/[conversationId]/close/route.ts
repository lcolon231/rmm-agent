// SPDX-License-Identifier: AGPL-3.0-only

import { getDashboardSession } from "@/lib/dashboard-session";
import { closeSupportConversation } from "@/lib/support";
import { handleCloseConversation } from "@/lib/support-route-core";

export const dynamic = "force-dynamic";

export async function POST(request: Request, context: { params: Promise<{ conversationId: string }> }) {
  const { conversationId } = await context.params;
  return handleCloseConversation(request, conversationId, {
    closeSupportConversation,
    getSession: getDashboardSession,
  });
}
