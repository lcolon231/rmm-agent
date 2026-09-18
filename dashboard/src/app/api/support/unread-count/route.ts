// SPDX-License-Identifier: AGPL-3.0-only
import { getDashboardSession } from "@/lib/dashboard-session";
import { getSupportUnreadCount } from "@/lib/support";

export const dynamic = "force-dynamic";

export async function GET() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") return Response.json({ error: "Unauthorized" }, { status: 401 });
  try {
    const unread = await getSupportUnreadCount(session.sessionToken);
    return Response.json({ unread }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ unread: 0 }, { headers: { "Cache-Control": "no-store" } });
  }
}
