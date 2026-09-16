// SPDX-License-Identifier: AGPL-3.0-only
"use client";
import { useEffect, useRef, useState } from "react";
import { chatStateFromUnknown, mergeMessages, readChatAccess, type ChatAccess, type ChatMessage, type ChatState } from "@/lib/support-chat-core";
import styles from "./support-chat-panel.module.css";

export function SupportChatPanel() {
  const access = useRef<ChatAccess | null>(null);
  const initialized = useRef(false);
  const busy = useRef(false);
  const cursor = useRef(0);
  const ended = useRef(false);
  const [state, setState] = useState<ChatState | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [draft, setDraft] = useState("");
  const [error, setError] = useState("");
  const [sending, setSending] = useState(false);
  const [expired, setExpired] = useState(false);

  async function request(action: string, payload?: object) {
    const auth = access.current;
    if (!auth) throw new Error("Open NodeLink Support on your computer to start a session.");
    const response = await fetch(`/api/chat/${auth.conversation}/${action}`, {
      method: payload ? "POST" : "GET", cache: "no-store", credentials: "omit",
      headers: { Authorization: `Bearer ${auth.token}`, "Content-Type": "application/json" },
      body: payload ? JSON.stringify(payload) : undefined, signal: AbortSignal.timeout(20000),
    });
    const body = await response.json();
    if (!response.ok) {
      if (response.status === 401 || response.status === 403) {
        ended.current = true;
        setExpired(true);
        throw new Error("This chat session has expired or was reopened. Open NodeLink Support again on your computer.");
      }
      if (body.code === "support_chat_conversation_closed") {
        ended.current = true;
        setState(s => s ? { ...s, status: "closed" } : s);
        throw new Error("This conversation is closed.");
      }
      if (body.code === "support_chat_notice_required") setState(s => s ? { ...s, notice_acknowledged: false } : s);
      throw new Error(body.code === "support_chat_message_limit" ? "This conversation has reached its message limit." : body.error ?? "Chat is temporarily unavailable.");
    }
    return body;
  }

  async function renew() {
    if (access.current && access.current.expires - Date.now() < 120000) {
      const refreshed = await request("refresh", {});
      access.current = { ...access.current, token: refreshed.token, expires: Date.parse(refreshed.token_expires_at) };
    }
  }

  useEffect(() => {
    if (!initialized.current) {
      initialized.current = true;
      access.current = readChatAccess(window.location.hash);
      window.history.replaceState(null, "", window.location.pathname);
    }
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      if (stopped || ended.current) return;
      if (!busy.current) {
        busy.current = true;
        try {
          await renew();
          const next = chatStateFromUnknown(await request(`messages?after=${cursor.current}`));
          if (!next) throw new Error("Chat returned an invalid response.");
          if (stopped) return;
          setState(next);
          setMessages(old => mergeMessages(old, next.messages));
          cursor.current = Math.max(cursor.current, ...next.messages.map(m => m.seq));
          if (access.current) access.current.expires = Date.parse(next.token_expires_at);
          ended.current = next.status === "closed";
          setError("");
        } catch (e) { if (!stopped) setError(e instanceof Error ? e.message : "Chat is unavailable."); }
        finally { busy.current = false; }
      }
      if (!stopped) timer = setTimeout(poll, 3000);
    }
    void poll();
    return () => { stopped = true; clearTimeout(timer); };
    // One polling loop per mounted page; credentials live only in memory.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function submit(action: "notice" | "messages") {
    if (busy.current || ended.current || !state) return;
    busy.current = true;
    setSending(true);
    setError("");
    try {
      await renew();
      const result = await request(action, action === "notice" ? { notice_version: state.notice_version } : { body: draft });
      if (action === "notice") setState({ ...state, notice_acknowledged: true });
      else {
        setMessages(old => mergeMessages(old, [result]));
        // The poll cursor advances only from polls, so a concurrent technician
        // reply before this send cannot be skipped.
        setDraft("");
      }
    } catch (e) { setError(e instanceof Error ? e.message : "Message delivery could not be confirmed. Check the transcript before retrying."); }
    finally { busy.current = false; setSending(false); }
  }

  const canSend = state?.status === "open" && state.notice_acknowledged && !expired;
  const tooLarge = new TextEncoder().encode(draft).length > 4096;
  return <main className={styles.page}><section className={styles.panel}>
    <header><span className={styles.brand}>NODELINK</span><h1>Support</h1><p>Talk with your IT support team.</p></header>
    {error && <p role="alert" className={styles.error}>{error}</p>}
    {!state && !error && <p role="status">Connecting to support…</p>}
    {state?.status === "closed" && <p role="status">This conversation is closed. You can close this tab.</p>}
    {state?.status === "open" && !state.notice_acknowledged && <section className={styles.notice} aria-label="Recording notice">
      <h2>Before you start</h2><p>This conversation is recorded and linked to your computer. Your IT support team can read it.
      {state.retention_days > 0 ? ` The configured retention period is ${state.retention_days} days after the conversation closes.` : " Automatic transcript deletion is disabled."}
      </p><p>Avoid sending passwords or other sensitive information.</p>
      <button disabled={sending} onClick={() => void submit("notice")}>I acknowledge — continue</button>
    </section>}
    <ol className={styles.messages} aria-label="Conversation" aria-live="polite" aria-relevant="additions">
      {messages.map(m => <li key={m.seq} className={m.sender === "end_user" ? styles.own : styles.reply}>
        <strong>{m.sender === "end_user" ? "You" : "Support team"}</strong><p>{m.body}</p><time dateTime={m.created_at}>{new Date(m.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</time>
      </li>)}
    </ol>
    <form onSubmit={e => { e.preventDefault(); void submit("messages"); }} className={styles.composer}>
      <label htmlFor="support-message">Your message</label>
      <textarea id="support-message" value={draft} onChange={e => setDraft(e.target.value)} disabled={!canSend || sending} rows={3} maxLength={4096} placeholder="How can we help?" />
      {tooLarge && <p role="alert">Message is too long (maximum 4,096 bytes).</p>}
      <button disabled={!canSend || sending || !draft.trim() || tooLarge}>{sending ? "Sending…" : "Send message"}</button>
    </form>
  </section></main>;
}
