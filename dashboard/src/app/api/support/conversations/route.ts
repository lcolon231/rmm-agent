// SPDX-License-Identifier: AGPL-3.0-only
import { getDashboardSession } from "@/lib/dashboard-session";
import { getSupportConversations } from "@/lib/support";

export const dynamic = "force-dynamic";

export async function GET() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") return Response.json({ error: "Unauthorized" }, { status: 401 });
  try {
    const conversations = await getSupportConversations(session.sessionToken);
    return Response.json({ conversations }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ error: "Support chat is temporarily unavailable." }, { status: 502 });
  }
}
