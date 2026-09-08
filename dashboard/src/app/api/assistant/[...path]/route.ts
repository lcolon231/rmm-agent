// SPDX-License-Identifier: AGPL-3.0-only
import { getDashboardSession } from "@/lib/dashboard-session";
import { handleAssistant } from "@/lib/assistant-route-core";
import { assistantRequest } from "@/lib/nodelink-assistant";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

async function handle(request: Request, context: { params: Promise<{ path: string[] }> }) {
  const { path } = await context.params;
  return handleAssistant(request, path, { getSession: getDashboardSession, send: assistantRequest });
}
export { handle as GET, handle as POST };
