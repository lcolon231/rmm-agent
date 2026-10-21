// SPDX-License-Identifier: AGPL-3.0-only

import { getDashboardSession } from "@/lib/dashboard-session";
import { postSupportReply } from "@/lib/support";
import { handlePostReply } from "@/lib/support-route-core";

export const dynamic = "force-dynamic";

export async function POST(request: Request, context: { params: Promise<{ conversationId: string }> }) {
  const { conversationId } = await context.params;
  return handlePostReply(request, conversationId, {
    getSession: getDashboardSession,
    postSupportReply,
  });
}
