// SPDX-License-Identifier: AGPL-3.0-only

import { MessagesSquare } from "lucide-react";
import { redirect } from "next/navigation";

import { PageHeader, PageStack } from "@/components/shell/page-header";
import { ChatCard, ChatPanes, SUPPORT_DESCRIPTION } from "@/components/support/chat-layout";
import { SupportConversationList } from "@/components/support/conversation-list";
import { EmptyState } from "@/components/ui/states";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getSupportConversations } from "@/lib/support";
import type { OperatorConversation } from "@/lib/support-chat-core";

export const dynamic = "force-dynamic";

export default async function SupportPage() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  let conversations: OperatorConversation[] | null = null;
  const result = await Promise.allSettled([getSupportConversations(session.sessionToken)]);
  if (result[0].status === "fulfilled") conversations = result[0].value;

  return (
    <PageStack>
      <PageHeader
        breadcrumb={[{ label: "Support" }, { label: "Support chat" }]}
        title="Support chat"
        description={SUPPORT_DESCRIPTION}
      />
      <ChatPanes list={<SupportConversationList conversations={conversations} />}>
        {conversations && conversations.length > 0 ? (
          <ChatCard label="Conversation">
            <EmptyState
              icon={MessagesSquare}
              title="Select a conversation"
              body="Open conversations are listed first. The unread count clears when you open a conversation."
            />
          </ChatCard>
        ) : null}
      </ChatPanes>
    </PageStack>
  );
}
