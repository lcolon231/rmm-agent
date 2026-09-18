// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";

import { SupportConversationView } from "@/components/support-conversation-view";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getSupportTranscript } from "@/lib/support";
import type { OperatorTranscript } from "@/lib/support-chat-core";

export const dynamic = "force-dynamic";

export default async function SupportConversationPage({ params }: { params: Promise<{ conversationId: string }> }) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");
  const { conversationId } = await params;

  // A cross-tenant or missing conversation throws (the API answers 404); the
  // view renders an unavailable state rather than leaking existence.
  let initial: OperatorTranscript | null = null;
  try {
    initial = await getSupportTranscript(session.sessionToken, conversationId);
  } catch {
    initial = null;
  }

  return <SupportConversationView conversationId={conversationId} initial={initial} />;
}
