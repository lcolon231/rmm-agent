// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";

import { PageHeader, PageStack } from "@/components/shell/page-header";
import { ChatPanes, SUPPORT_DESCRIPTION } from "@/components/support/chat-layout";
import { SupportConversationList } from "@/components/support/conversation-list";
import { SupportConversationView } from "@/components/support-conversation-view";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getSupportConversations, getSupportTranscript } from "@/lib/support";
import type { OperatorConversation, OperatorTranscript } from "@/lib/support-chat-core";

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

  // The list pane is loaded after the transcript, so the conversation just
  // opened already shows its unread count cleared. Its failure never hides
  // the thread.
  let conversations: OperatorConversation[] | null = null;
  try {
    conversations = await getSupportConversations(session.sessionToken);
  } catch {
    conversations = null;
  }

  return (
    <PageStack>
      <PageHeader
        breadcrumb={[{ label: "Support" }, { label: "Support chat", href: "/support" }, { label: initial?.endpoint ?? "Conversation" }]}
        title="Support chat"
        description={SUPPORT_DESCRIPTION}
      />
      <ChatPanes list={<SupportConversationList conversations={conversations} selectedId={conversationId} />}>
        <SupportConversationView conversationId={conversationId} initial={initial} />
      </ChatPanes>
    </PageStack>
  );
}
