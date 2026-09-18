// SPDX-License-Identifier: AGPL-3.0-only
"use client";
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
import styles from "./support-chat-panel.module.css";

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
      <>
        <header className="enrollment-page-head"><div><span>Support chat</span><h1>Conversation unavailable</h1><p>This conversation could not be loaded. It may not exist or may be on an endpoint you cannot see.</p></div></header>
        <p><Link href="/support">← Back to Support chat</Link></p>
      </>
    );
  }

  return (
    <>
      <header className="enrollment-page-head">
        <div>
          <span>Support chat · {status}</span>
          <h1>{endpoint}</h1>
          <p>{initial.subject ?? "Support conversation"}</p>
        </div>
        <div style={{ display: "flex", gap: "0.75rem", alignItems: "center", flexWrap: "wrap" }}>
          <Link href="/support" className="monitoring-readonly-note">← All conversations</Link>
          <button type="button" onClick={() => void close()} disabled={status === "closed"}>{status === "closed" ? "Closed" : "Close conversation"}</button>
        </div>
      </header>

      <section className="enrollment-panel">
        {error && <p role="alert" className={styles.error}>{error}</p>}
        <ol className={styles.messages} aria-label="Conversation" aria-live="polite" aria-relevant="additions">
          {messages.map((m) => (
            <li key={m.seq} className={m.sender === "technician" ? styles.own : styles.reply}>
              <strong>{m.sender === "technician" ? (m.operator_email ?? "Technician") : "Endpoint user"}</strong>
              <p>{m.body}</p>
              <time dateTime={m.created_at}>{formatChatTimestamp(m.created_at)}</time>
            </li>
          ))}
        </ol>
        <form onSubmit={(e) => { e.preventDefault(); void send(); }} className={styles.composer}>
          <label htmlFor="support-reply">Reply</label>
          <textarea id="support-reply" value={draft} onChange={(e) => setDraft(e.target.value)} disabled={status === "closed" || sending} rows={3} maxLength={4096} placeholder={status === "closed" ? "This conversation is closed." : "Type a reply…"} />
          <button disabled={status === "closed" || sending || !draft.trim()}>{sending ? "Sending…" : "Send reply"}</button>
        </form>
      </section>
    </>
  );
}
