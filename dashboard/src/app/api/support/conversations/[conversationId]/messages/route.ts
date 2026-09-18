// SPDX-License-Identifier: AGPL-3.0-only
import { getDashboardSession } from "@/lib/dashboard-session";
import { postSupportReply } from "@/lib/support";

export const dynamic = "force-dynamic";

export async function POST(request: Request, context: { params: Promise<{ conversationId: string }> }) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") return Response.json({ error: "Unauthorized" }, { status: 401 });
  if (request.headers.get("origin") && request.headers.get("origin") !== new URL(request.url).origin) {
    return Response.json({ error: "Request origin refused." }, { status: 403 });
  }
  const { conversationId } = await context.params;
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "Invalid request." }, { status: 400 });
  }
  const text = (body as { body?: unknown })?.body;
  if (typeof text !== "string" || text.trim() === "" || new TextEncoder().encode(text).length > 4096) {
    return Response.json({ error: "Message must be between 1 and 4096 bytes." }, { status: 400 });
  }
  try {
    const message = await postSupportReply(session.sessionToken, conversationId, text);
    return Response.json(message, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ error: "Reply could not be delivered." }, { status: 502 });
  }
}
