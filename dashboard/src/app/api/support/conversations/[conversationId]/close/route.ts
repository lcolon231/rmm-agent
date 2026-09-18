// SPDX-License-Identifier: AGPL-3.0-only
import { getDashboardSession } from "@/lib/dashboard-session";
import { closeSupportConversation } from "@/lib/support";

export const dynamic = "force-dynamic";

export async function POST(request: Request, context: { params: Promise<{ conversationId: string }> }) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") return Response.json({ error: "Unauthorized" }, { status: 401 });
  if (request.headers.get("origin") && request.headers.get("origin") !== new URL(request.url).origin) {
    return Response.json({ error: "Request origin refused." }, { status: 403 });
  }
  const { conversationId } = await context.params;
  try {
    await closeSupportConversation(session.sessionToken, conversationId);
    return Response.json({ status: "closed" }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ error: "Could not close the conversation." }, { status: 502 });
  }
}
