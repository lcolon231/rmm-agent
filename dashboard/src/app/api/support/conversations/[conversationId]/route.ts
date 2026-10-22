// SPDX-License-Identifier: AGPL-3.0-only

import { getDashboardSession } from "@/lib/dashboard-session";
import { getSupportTranscript } from "@/lib/support";
import { handleGetTranscript } from "@/lib/support-route-core";

export const dynamic = "force-dynamic";

export async function GET(request: Request, context: { params: Promise<{ conversationId: string }> }) {
  const { conversationId } = await context.params;
  return handleGetTranscript(request, conversationId, {
    getSession: getDashboardSession,
    getSupportTranscript,
  });
}
