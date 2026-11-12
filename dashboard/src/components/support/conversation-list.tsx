// SPDX-License-Identifier: AGPL-3.0-only

import Link from "next/link";

import { formatChatTimestamp, type OperatorConversation } from "@/lib/support-chat-core";

import { cx, focusRing } from "../ui/cx";
import { EmptyState, ErrorState } from "../ui/states";
import { ChatCard, UnreadPill } from "./chat-layout";

function Row({ conversation, selected }: { conversation: OperatorConversation; selected: boolean }) {
  const time = formatChatTimestamp(conversation.last_message_at);
  return (
    <li className="border-t border-(--line) first:border-t-0">
      <Link
        href={`/support/${encodeURIComponent(conversation.id)}`}
        aria-current={selected ? "page" : undefined}
        className={cx(
          "grid grid-cols-[minmax(0,1fr)_auto] gap-x-3 gap-y-0.5 px-5 py-3 text-(--ink) no-underline hover:bg-(--primary-tint)",
          selected && "bg-(--primary-tint)",
          focusRing,
        )}
      >
        <span className="truncate font-(family-name:--font-data) text-sm font-semibold">
          {conversation.endpoint ?? conversation.agent_id}
        </span>
        <span className="text-xs whitespace-nowrap text-(--muted)">{time || "No messages yet"}</span>
        <span className="truncate text-[13px] text-(--muted)">
          {conversation.status === "closed" ? "Closed · " : ""}
          {conversation.subject ?? "No subject"}
        </span>
        <span className="justify-self-end">{conversation.unread > 0 ? <UnreadPill count={conversation.unread} /> : null}</span>
      </Link>
    </li>
  );
}

/**
 * Conversation list pane. Open conversations first, in the server's order;
 * closed ones follow and remain viewable for their retained transcript.
 */
export function SupportConversationList({ conversations, selectedId }: {
  conversations: OperatorConversation[] | null;
  selectedId?: string;
}) {
  const open = conversations?.filter((c) => c.status === "open") ?? [];
  const closed = conversations?.filter((c) => c.status === "closed") ?? [];
  return (
    <ChatCard label="Conversations">
      <header className="border-b border-(--line) px-5 py-4">
        <h2 className="m-0 text-base font-semibold text-(--ink)">Conversations</h2>
        <p className="m-0 mt-0.5 text-[13px] text-(--muted)">
          {conversations === null ? "Unavailable" : `${open.length} open · ${closed.length} closed`}
        </p>
      </header>
      {conversations === null ? (
        <ErrorState
          title="Support chat could not be loaded"
          body="No conversations are shown because the response could not be verified"
        />
      ) : conversations.length === 0 ? (
        <EmptyState
          title="No conversations"
          body="When a user opens NodeLink Support on an endpoint you can see, it appears here."
        />
      ) : (
        <ul className="m-0 list-none p-0" aria-label="Open and closed conversations">
          {[...open, ...closed].map((c) => <Row key={c.id} conversation={c} selected={c.id === selectedId} />)}
        </ul>
      )}
    </ChatCard>
  );
}
