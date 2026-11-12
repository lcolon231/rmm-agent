// SPDX-License-Identifier: AGPL-3.0-only
"use client";
import { CircleAlert } from "lucide-react";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import {
  formatChatTimestamp,
  mergeMessages,
  operatorTranscriptFromUnknown,
  transcriptMessageFromUnknown,
  type OperatorTranscript,
  type TranscriptMessage,
} from "@/lib/support-chat-core";

import { BubbleMeta, ChatCard, ChatNotice, ThreadHeader, bubbleClass, messageListClass } from "./support/chat-layout";
import { Button } from "./ui/button";
import { cx, focusRing } from "./ui/cx";
import { Textarea } from "./ui/field";
import { ErrorState } from "./ui/states";
import { StatusBadge } from "./ui/status-badge";

export function SupportConversationView({ conversationId, initial }: { conversationId: string; initial: OperatorTranscript | null }) {
  const [messages, setMessages] = useState<TranscriptMessage[]>(initial?.messages ?? []);
  const [status, setStatus] = useState<"open" | "closed">(initial?.status ?? "open");
  const [draft, setDraft] = useState("");
  const [error, setError] = useState("");
  const [sending, setSending] = useState(false);
  const busy = useRef(false);
  const endpoint = initial?.endpoint ?? initial?.agent_id ?? conversationId;

  useEffect(() => {
    if (!initial) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      if (stopped) return;
      if (!busy.current) {
        try {
          const response = await fetch(`/api/support/conversations/${encodeURIComponent(conversationId)}`, { cache: "no-store" });
          if (response.ok) {
            const next = operatorTranscriptFromUnknown(await response.json());
            if (next && !stopped) {
              setMessages((old) => mergeMessages(old, next.messages));
              setStatus(next.status);
            }
          }
        } catch { /* transient; next poll retries */ }
      }
      if (!stopped) timer = setTimeout(poll, 3000);
    }
    timer = setTimeout(poll, 3000);
    return () => { stopped = true; clearTimeout(timer); };
  }, [conversationId, initial]);

  async function send() {
    if (busy.current || sending || status === "closed" || !draft.trim()) return;
    busy.current = true;
    setSending(true);
    setError("");
    try {
      const response = await fetch(`/api/support/conversations/${encodeURIComponent(conversationId)}/messages`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ body: draft }),
      });
      const raw = await response.json();
      if (!response.ok) throw new Error(raw?.error ?? "Reply could not be delivered.");
      const message = transcriptMessageFromUnknown(raw);
      if (message) setMessages((old) => mergeMessages(old, [message]));
      setDraft("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Reply could not be delivered.");
    } finally {
      busy.current = false;
      setSending(false);
    }
  }

  async function close() {
    if (busy.current || status === "closed") return;
    busy.current = true;
    setError("");
    try {
      const response = await fetch(`/api/support/conversations/${encodeURIComponent(conversationId)}/close`, { method: "POST", headers: { "Content-Type": "application/json" } });
      if (!response.ok) throw new Error("Could not close the conversation.");
      setStatus("closed");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not close the conversation.");
    } finally {
      busy.current = false;
    }
  }

  if (!initial) {
    return (
      <ChatCard label="Conversation">
        <ErrorState
          title="Conversation unavailable"
          body="This conversation could not be loaded. It may not exist or may be on an endpoint you cannot see"
        />
        <p className="m-0 px-5 pb-5 text-center text-sm">
          <Link href="/support" className={cx("rounded text-(--primary-strong)", focusRing)}>Back to Support chat</Link>
        </p>
      </ChatCard>
    );
  }

  const closed = status === "closed";
  const context = [
    initial.subject ?? "Support conversation",
    initial.opened_by === "end_user" ? "Started by the user" : "Started by a technician",
  ].join(" · ");

  return (
    <ChatCard label="Conversation">
      <ThreadHeader
        title={<span className="font-(family-name:--font-data)">{endpoint}</span>}
        status={<StatusBadge tone={closed ? "off" : "warn"}>{closed ? "Closed" : "Open"}</StatusBadge>}
        context={context}
        actions={
          <Button size="compact" onClick={() => void close()} disabled={closed}>
            {closed ? "Closed" : "Close conversation"}
          </Button>
        }
      />
      {error && (
        <p role="alert" className="m-0 flex items-center gap-2 border-b border-(--line) bg-(--red-soft) px-5 py-3 text-sm text-(--red)">
          <CircleAlert size={16} aria-hidden="true" />
          {error}
        </p>
      )}
      <ol className={messageListClass} aria-label="Conversation" aria-live="polite" aria-relevant="additions">
        {messages.length === 0 ? <li className={bubbleClass("system")}>No messages yet.</li> : null}
        {messages.map((m) => (
          <li key={m.seq} className={bubbleClass(m.sender === "technician" ? "mine" : "theirs")}>
            <BubbleMeta
              who={m.sender === "technician" ? (m.operator_email ?? "Technician") : "User"}
              time={formatChatTimestamp(m.created_at)}
              dateTime={m.created_at}
            />
            <p className="m-0 whitespace-pre-wrap">{m.body}</p>
          </li>
        ))}
        {closed ? <li className={bubbleClass("system")}>This conversation is closed.</li> : null}
      </ol>
      <ChatNotice>
        <p className="m-0">Please don’t ask for or share patient details in chat. The user can read every reply you send.</p>
      </ChatNotice>
      <form onSubmit={(e) => { e.preventDefault(); void send(); }} className="grid gap-3 border-t border-(--line) px-5 py-4">
        <Textarea
          id="support-reply"
          label="Reply"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          disabled={closed || sending}
          rows={3}
          maxLength={4096}
          placeholder={closed ? "This conversation is closed." : "Write a reply"}
        />
        <div className="flex justify-end">
          <Button type="submit" variant="primary" disabled={closed || sending || !draft.trim()}>
            {sending ? "Sending…" : "Send"}
          </Button>
        </div>
      </form>
    </ChatCard>
  );
}
