// SPDX-License-Identifier: AGPL-3.0-only
"use client";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import styles from "./assistant.module.css";

type Source = { endpoint_id: string; label: string; last_seen_at: string | null; observed_at: string };
type Evidence = { tool: string; outcome: string; observed_at?: string; data: unknown; sources: Source[] };
type Run = { id: string; request_id: string; status: string; created_at: string; question: string; answer: string; evidence: Evidence[] };
type Conversation = { id: string; expires_at: string; runs: Run[] };
type History = { id: string; created_at: string; expires_at: string };

async function api<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch(`/api/assistant/${path}`, { cache: "no-store", method: body === undefined ? "GET" : "POST",
    headers: body === undefined ? undefined : { "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error ?? "Assistant unavailable.");
  return value as T;
}

function timestamp(value: string | null | undefined) {
  return value ? new Date(value).toLocaleString() : "Never reported";
}

export function AssistantChat({ clients, initialClientId, endpointId, state }: {
  clients: { id: string; name: string }[]; initialClientId?: string; endpointId?: string; state: string;
}) {
  const [clientId, setClientId] = useState(initialClientId ?? "");
  const [history, setHistory] = useState<History[]>([]);
  const [conversation, setConversation] = useState<Conversation | null>(null);
  const [message, setMessage] = useState(endpointId ? `Investigate endpoint ${endpointId}: show its status and telemetry.` : "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [retry, setRetry] = useState<{ text: string; id: string } | null>(null);
  const active = useRef<{ conversation: string; request: string } | null>(null);
  const generation = useRef(0);
  const transcript = useRef<HTMLDivElement>(null);

  useEffect(() => { transcript.current?.scrollTo({ top: transcript.current.scrollHeight, behavior: "smooth" }); }, [conversation, busy]);
  useEffect(() => {
    if (!clientId || state !== "available") return;
    let stale = false;
    api<{ items: History[] }>(`conversations?client_id=${encodeURIComponent(clientId)}`)
      .then(value => { if (!stale) setHistory(value.items); })
      .catch(() => { if (!stale) setError("Conversation history could not be loaded. Refresh to retry."); });
    return () => { stale = true; };
  }, [clientId, state]);

  async function load(id: string) {
    setBusy(true); setError(""); setNotice(""); setRetry(null);
    const version = ++generation.current;
    try {
      const data = await api<Conversation>(`conversations/${id}`);
      if (version === generation.current) setConversation(data);
    } catch (err) {
      setConversation(null); setError((err as Error).message);
    } finally { setBusy(false); }
  }

  async function send(text: string, requestId = crypto.randomUUID()) {
    if (!text.trim() || !clientId || busy) return;
    setBusy(true); setError(""); setNotice(""); setRetry(null);
    const version = ++generation.current;
    try {
      const current = conversation ?? await api<Conversation>("conversations", { client_id: clientId });
      setConversation(current);
      active.current = { conversation: current.id, request: requestId };
      setNotice("Investigating the selected client…");
      const result = await api<Conversation>(`conversations/${current.id}/runs`, { request_id: requestId, message: text });
      if (version === generation.current) {
        setConversation(result); setMessage(""); setNotice("");
        if (result.runs.at(-1)?.status === "failed") setRetry({ text, id: crypto.randomUUID() });
      }
      const list = await api<{ items: History[] }>(`conversations?client_id=${clientId}`);
      setHistory(list.items);
    } catch (err) {
      if (version === generation.current) {
        setConversation(current => current ? { ...current, runs: [] } : null); setError((err as Error).message);
        // Keep identity on transport failure so retry cannot duplicate a charged run.
        setRetry({ text, id: requestId });
      }
    } finally { active.current = null; setBusy(false); }
  }

  async function cancel(request = active.current) {
    if (!request) return;
    try {
      await api(`conversations/${request.conversation}/runs/${request.request}/cancel`, {});
      ++generation.current;
      setNotice("Cancellation confirmed. Refresh history to see the final state.");
      setConversation(await api<Conversation>(`conversations/${request.conversation}`));
    } catch (err) { setError(`Cancellation could not be confirmed. ${(err as Error).message}`); }
  }

  if (state !== "available") return <section className={styles.unavailable} role="status"><h1>AI assistant</h1>
    <p>{state === "disabled" ? "The assistant is not enabled for this operator." : state === "unconfigured" ? "The assistant is awaiting server configuration." : "The assistant is temporarily unavailable."}</p>
    <p>Endpoint management remains available.</p><Link href="/endpoints">Open endpoints</Link><button onClick={() => window.location.reload()}>Retry</button></section>;

  return <section className={styles.assistant}>
    <header className={styles.heading}><div><span>READ-ONLY · PILOT</span><h1>Investigate with NodeLink</h1>
      <p>Ask about your endpoints. Answers use reported data and your current permissions.</p></div></header>
    <div className={styles.toolbar}><label>Client<select value={clientId} disabled={busy} onChange={event => {
      ++generation.current; setClientId(event.target.value); setConversation(null); setHistory([]); setError(""); setNotice(""); setRetry(null); setMessage("");
    }}><option value="">Select one client</option>{clients.map(client => <option key={client.id} value={client.id}>{client.name}</option>)}</select></label>
      <button disabled={busy || !clientId} onClick={() => { setConversation(null); setRetry(null); setMessage(""); setNotice(""); }}>New conversation</button>
      <button disabled={busy || !conversation} onClick={() => conversation && load(conversation.id)}>Refresh history</button></div>
    <div className={styles.workspace}><aside className={styles.history} aria-label="Private conversation history"><h2>Your conversations</h2>
      <p>Private to you. Expires after 30 days.</p>
      {history.length === 0 ? <p>No conversations loaded.</p> : history.map(item => <button disabled={busy} aria-current={conversation?.id === item.id ? "true" : undefined}
        key={item.id} onClick={() => load(item.id)}>{timestamp(item.created_at)}</button>)}
    </aside><div className={styles.chat}>
      <div className={styles.transcript} ref={transcript} role="log" aria-label="Assistant conversation" aria-live="polite" aria-busy={busy}>
        {!conversation?.runs.length && <div className={styles.welcome}><h2>Start with an investigation</h2><p>Select a client, then ask a question.</p>
          {["Which endpoints are offline?", "Show active alerts and explain what they mean.", "Summarize patch compliance."].map(text => <button disabled={!clientId || busy} key={text} onClick={() => { setMessage(text); void send(text); }}>{text}</button>)}</div>}
        {conversation?.runs.map(run => <article key={run.id} className={styles.turn}><div className={styles.question}><strong>You</strong><p>{run.question}</p></div>
          <div className={styles.answer}><strong>NodeLink · {run.status}</strong><small>{timestamp(run.created_at)}</small>
            {run.status === "running" ? <><p>Investigation in progress. Refresh history for the result.</p><button onClick={() => cancel({ conversation: conversation.id, request: run.request_id })}>Cancel investigation</button></> :
              <><p className={styles.interpretation}>{run.answer || (run.status === "cancelled" ? "Investigation cancelled." : "No answer available.")}</p>
                <small>Model interpretation; verify against the observed evidence below.</small></>}
            {run.evidence.map((item, index) => <section className={styles.evidence} key={index}><strong>{item.tool.replaceAll("_", " ")} · {item.outcome}</strong>
              {item.observed_at && <small>Read {timestamp(item.observed_at)}</small>}
              {item.sources.length > 0 && <ul>{item.sources.map(source => <li key={source.endpoint_id}>
                <Link href={`/endpoints/${encodeURIComponent(source.endpoint_id)}`}>{source.label || source.endpoint_id}</Link><span>Last seen: {timestamp(source.last_seen_at)}</span></li>)}</ul>}
              <details><summary>Observed data and limitations</summary><pre>{JSON.stringify(item.data, null, 2)}</pre></details></section>)}
            {run.status === "failed" && <button disabled={busy} onClick={() => send(run.question)}>Retry investigation</button>}
          </div></article>)}
      </div>
      {error && <p role="alert" className={styles.error}>{error}</p>}
      {notice && <p role="status">{notice}</p>}
      {retry && <button disabled={busy} onClick={() => send(retry.text, retry.id)}>Retry last request</button>}
      <form className={styles.composer} onSubmit={event => { event.preventDefault(); void send(message); }}>
        <label htmlFor="assistant-message">Ask about the selected client</label>
        <textarea id="assistant-message" value={message} maxLength={4000} rows={3} disabled={busy || !clientId} onChange={event => setMessage(event.target.value)} placeholder="Which endpoints are offline?" />
        <div><small>{message.length}/4,000 · Avoid entering secrets or personal information.</small>
          {busy ? <button type="button" onClick={() => cancel()}>Cancel</button> : <button type="submit" disabled={!clientId || !message.trim()}>Send question</button>}</div>
      </form>
    </div></div>
  </section>;
}
