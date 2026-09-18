// SPDX-License-Identifier: AGPL-3.0-only
import { getDashboardSession } from "@/lib/dashboard-session";
import { getSupportTranscript } from "@/lib/support";

export const dynamic = "force-dynamic";

export async function GET(_request: Request, context: { params: Promise<{ conversationId: string }> }) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") return Response.json({ error: "Unauthorized" }, { status: 401 });
  const { conversationId } = await context.params;
  try {
    const transcript = await getSupportTranscript(session.sessionToken, conversationId);
    return Response.json(transcript, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ error: "Conversation is unavailable." }, { status: 502 });
  }
}
