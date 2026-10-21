// SPDX-License-Identifier: AGPL-3.0-only

import { getDashboardSession } from "@/lib/dashboard-session";
import { revokeAgent } from "@/lib/enrollment";
import { handleRevokeAgent } from "@/lib/enrollment-route-core";

export const dynamic = "force-dynamic";

export async function POST(request: Request, context: { params: Promise<{ agentId: string }> }) {
  const { agentId } = await context.params;
  return handleRevokeAgent(request, agentId, {
    getSession: getDashboardSession,
    revokeAgent,
  });
}
