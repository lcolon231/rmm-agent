// SPDX-License-Identifier: AGPL-3.0-only

import { MessageCircle, MessagesSquare } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";

import { getDashboardSession } from "@/lib/dashboard-session";
import { getSupportConversations } from "@/lib/support";
import { formatChatTimestamp, type OperatorConversation } from "@/lib/support-chat-core";

export const dynamic = "force-dynamic";

export default async function SupportPage() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  let conversations: OperatorConversation[] | null = null;
  const result = await Promise.allSettled([getSupportConversations(session.sessionToken)]);
  if (result[0].status === "fulfilled") conversations = result[0].value;
  const open = conversations?.filter((c) => c.status === "open") ?? [];
  const closed = conversations?.filter((c) => c.status === "closed") ?? [];

  return (
    <>
      <header className="enrollment-page-head">
        <div>
          <span>Technician queue</span>
          <h1>Support chat</h1>
          <p>Conversations opened from endpoints you can see. Open conversations first; the unread count clears when you open a conversation.</p>
        </div>
        <span className="monitoring-readonly-note">Live queue</span>
      </header>

      <section className="enrollment-panel">
        <header>
          <div><span>Open</span><h2>{conversations === null ? "Unavailable" : `${open.length} open`}</h2><small>A conversation stays open until a technician closes it.</small></div>
          <MessagesSquare aria-hidden="true" size={19} />
        </header>
        {conversations === null ? (
          <div className="enrollment-empty" role="alert"><MessageCircle size={24} /><h3>Support chat could not be loaded</h3><p>No conversations are shown because the response could not be verified.</p></div>
        ) : open.length === 0 ? (
          <div className="enrollment-empty"><MessageCircle size={24} /><h3>No open conversations</h3><p>When a user opens NodeLink Support on an endpoint you can see, it appears here.</p></div>
        ) : (
          <div className="enrollment-table-wrap"><table>
            <thead><tr><th>Endpoint</th><th>Subject</th><th>Last message</th><th>Unread</th></tr></thead>
            <tbody>{open.map((c) => (
              <tr key={c.id}>
                <td><Link href={`/support/${encodeURIComponent(c.id)}`}>{c.endpoint ?? c.agent_id}</Link><code>{c.agent_id}</code></td>
                <td>{c.subject ?? "—"}</td>
                <td>{formatChatTimestamp(c.last_message_at) || "—"}</td>
                <td>{c.unread > 0 ? <span className="nav-count">{c.unread}</span> : "0"}</td>
              </tr>
            ))}</tbody>
          </table></div>
        )}
      </section>

      {closed.length > 0 ? (
        <section className="enrollment-panel">
          <header>
            <div><span>Closed</span><h2>{`${closed.length} closed`}</h2><small>Closed conversations remain viewable for their retained transcript.</small></div>
            <MessageCircle aria-hidden="true" size={19} />
          </header>
          <div className="enrollment-table-wrap"><table>
            <thead><tr><th>Endpoint</th><th>Subject</th><th>Last message</th></tr></thead>
            <tbody>{closed.map((c) => (
              <tr key={c.id}>
                <td><Link href={`/support/${encodeURIComponent(c.id)}`}>{c.endpoint ?? c.agent_id}</Link><code>{c.agent_id}</code></td>
                <td>{c.subject ?? "—"}</td>
                <td>{formatChatTimestamp(c.last_message_at) || "—"}</td>
              </tr>
            ))}</tbody>
          </table></div>
        </section>
      ) : null}
    </>
  );
}
