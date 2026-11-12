// SPDX-License-Identifier: AGPL-3.0-only
"use client";
import { CircleAlert, Plus, RefreshCw } from "lucide-react";
import Link from "next/link";
import { useEffect, useRef, useState, type ReactNode } from "react";

import { PageHeader, PageStack } from "../shell/page-header";
import { BubbleMeta, ChatCard, ChatNotice, ChatPanes, ThreadHeader, bubbleClass } from "../support/chat-layout";
import { Button, ButtonLink } from "../ui/button";
import { cx, focusRing } from "../ui/cx";
import { Select, Textarea } from "../ui/field";
import { cardClass } from "../ui/stat-tile";
import { StatusBadge, type StatusTone } from "../ui/status-badge";

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

// Run states from server/app/core/assistant/service.py: running, completed,
// failed, cancelled. Anything else is shown as reported, never as completed.
function runTone(status: string): StatusTone {
  if (status === "completed") return "ok";
  if (status === "running") return "info";
  if (status === "failed") return "crit";
  return "off";
}

function runLabel(status: string) {
  if (status === "completed") return "Completed";
  if (status === "running") return "Running";
  if (status === "failed") return "Failed";
  if (status === "cancelled") return "Cancelled";
  return status;
}

// Verified against server/app/core/assistant/tools.py (a closed registry of
// read-only adapters; endpoint actions are absent from api/assistant.py) and
// provider.py (questions and tool results go to the configured AI provider).
export const ASSISTANT_SCOPE_NOTE =
  "The assistant reads only device information NodeLink already holds: endpoints, check-ins, inventory, alerts and update compliance. The assistant cannot run commands or change devices or settings.";
export const ASSISTANT_PROVIDER_NOTE =
  "Your question and the information it reads are sent to an external AI service. Don’t type patient details into a question.";

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

  useEffect(() => { transcript.current?.scrollTo?.({ top: transcript.current.scrollHeight, behavior: "smooth" }); }, [conversation, busy]);
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

  const header = (actions?: ReactNode) => <PageHeader breadcrumb={[{ label: "Support" }, { label: "AI assistant" }]} title="AI assistant"
    description="Ask about the selected client’s devices in plain language. The assistant reads device information NodeLink already holds; it cannot run commands or change devices or settings."
    actions={actions} />;

  if (state !== "available") return <PageStack>{header()}
    <section className={cx(cardClass, "grid gap-3 p-5")} role="status" aria-label="Assistant status">
      <p className="m-0 text-base font-semibold text-(--ink)">{state === "disabled" ? "The assistant is not enabled for this operator." : state === "unconfigured" ? "The assistant is awaiting server configuration." : "The assistant is temporarily unavailable."}</p>
      <p className="m-0 text-sm text-(--muted)">Endpoint management remains available.</p>
      <div className="flex flex-wrap gap-2">
        <ButtonLink href="/endpoints">Open endpoints</ButtonLink>
        <Button variant="quiet" icon={RefreshCw} onClick={() => window.location.reload()}>Retry</Button>
      </div>
    </section>
  </PageStack>;

  const clientName = clients.find(client => client.id === clientId)?.name;
  const title = conversation?.runs[0]?.question ?? "New conversation";

  return <PageStack>
    {header(<Button variant="primary" icon={Plus} disabled={busy || !clientId}
      onClick={() => { setConversation(null); setRetry(null); setMessage(""); setNotice(""); }}>New conversation</Button>)}
    <ChatPanes list={<ChatCard label="Private conversation history">
      <div className="border-b border-(--line) px-5 py-4">
        <Select label="Client" value={clientId} disabled={busy} onChange={event => {
          ++generation.current; setClientId(event.target.value); setConversation(null); setHistory([]); setError(""); setNotice(""); setRetry(null); setMessage("");
        }}><option value="">Select one client</option>{clients.map(client => <option key={client.id} value={client.id}>{client.name}</option>)}</Select>
      </div>
      <div className="px-5 pt-4 pb-2">
        <h2 className="m-0 text-base font-semibold text-(--ink)">Your conversations</h2>
        <p className="m-0 mt-0.5 text-[13px] text-(--muted)">Private to you. Expires after 30 days.</p>
      </div>
      {history.length === 0 ? <p className="m-0 px-5 pb-4 text-sm text-(--muted)">No conversations loaded.</p> :
        <ul className="m-0 list-none p-0 pb-2">{history.map(item => <li key={item.id}>
          <button type="button" disabled={busy} aria-current={conversation?.id === item.id ? "true" : undefined}
            className={cx("block w-full px-5 py-2.5 text-left text-sm text-(--ink) hover:bg-(--primary-tint) disabled:cursor-not-allowed disabled:text-(--muted)",
              conversation?.id === item.id && "bg-(--primary-tint) font-semibold", focusRing)}
            onClick={() => load(item.id)}>{timestamp(item.created_at)}</button>
        </li>)}</ul>}
    </ChatCard>}>
      <ChatCard label="Assistant thread">
        <ThreadHeader title={title} context={`${clientName ? `Looking at: ${clientName}` : "No client selected"} · read-only`}
          actions={<Button size="compact" variant="quiet" icon={RefreshCw} disabled={busy || !conversation}
            onClick={() => conversation && load(conversation.id)}>Refresh history</Button>} />
        <div className="flex max-h-[60vh] min-h-[320px] flex-col gap-3 overflow-y-auto p-5" ref={transcript} role="log"
          aria-label="Assistant conversation" aria-live="polite" aria-busy={busy}>
          {!conversation?.runs.length && <div className="grid max-w-[480px] gap-3 py-4">
            <h3 className="m-0 text-base font-semibold text-(--ink)">Start with an investigation</h3>
            <p className="m-0 text-sm text-(--muted)">Select a client, then ask a question.</p>
            {["Which endpoints are offline?", "Show active alerts and explain what they mean.", "Summarize patch compliance."].map(text =>
              <Button key={text} className="justify-start" disabled={!clientId || busy} onClick={() => { setMessage(text); void send(text); }}>{text}</Button>)}
          </div>}
          {conversation?.runs.map(run => <article key={run.id} className="flex flex-col gap-3">
            <div className={bubbleClass("mine")}>
              <BubbleMeta who="You" time={timestamp(run.created_at)} dateTime={run.created_at} />
              <p className="m-0 whitespace-pre-wrap">{run.question}</p>
            </div>
            <div className={cx(bubbleClass("theirs"), "grid gap-2")}>
              <div className="flex flex-wrap items-center gap-2">
                <BubbleMeta who="NodeLink" time={timestamp(run.created_at)} dateTime={run.created_at} />
                <StatusBadge tone={runTone(run.status)}>{runLabel(run.status)}</StatusBadge>
              </div>
              {run.status === "running" ? <>
                <p className="m-0">Investigation in progress. Refresh history for the result.</p>
                <div><Button size="compact" onClick={() => cancel({ conversation: conversation.id, request: run.request_id })}>Cancel investigation</Button></div>
              </> : <>
                <p className="m-0 leading-relaxed whitespace-pre-wrap">{run.answer || (run.status === "cancelled" ? "Investigation cancelled." : "No answer available.")}</p>
                <p className="m-0 text-xs text-(--muted)">Model interpretation; verify against the observed evidence below.</p>
              </>}
              {run.evidence.map((item, index) => <section className="grid gap-1 rounded-lg border border-(--line) bg-(--paper) p-3 text-[13px]" key={index}>
                <strong className="font-semibold text-(--ink)">{item.tool.replaceAll("_", " ")} · {item.outcome}</strong>
                {item.observed_at && <p className="m-0 text-xs text-(--muted)">Read {timestamp(item.observed_at)}</p>}
                {item.sources.length > 0 && <ul className="m-0 list-none p-0">{item.sources.map(source =>
                  <li key={source.endpoint_id} className="flex flex-wrap justify-between gap-x-3 border-b border-(--line) py-1.5 last:border-b-0">
                    <Link href={`/endpoints/${encodeURIComponent(source.endpoint_id)}`}
                      className={cx("rounded font-(family-name:--font-data) text-(--primary-strong) [overflow-wrap:anywhere]", focusRing)}>{source.label || source.endpoint_id}</Link>
                    <span className="text-xs text-(--muted)">Last seen: {timestamp(source.last_seen_at)}</span>
                  </li>)}</ul>}
                <details>
                  <summary className={cx("cursor-pointer rounded py-1 text-(--primary-strong)", focusRing)}>Observed data and limitations</summary>
                  <pre className="m-0 max-h-[330px] overflow-auto rounded-lg bg-(--ink-deep) p-3 font-(family-name:--font-data) text-xs whitespace-pre-wrap text-(--chrome-text) [overflow-wrap:anywhere]">{JSON.stringify(item.data, null, 2)}</pre>
                </details>
              </section>)}
              {run.status === "failed" && <div><Button size="compact" disabled={busy} onClick={() => send(run.question)}>Retry investigation</Button></div>}
            </div>
          </article>)}
          {notice && <p role="status" className={bubbleClass("system")}>{notice}</p>}
        </div>
        {error && <p role="alert" className="m-0 flex items-center gap-2 border-t border-(--line) bg-(--red-soft) px-5 py-3 text-sm text-(--red)">
          <CircleAlert size={16} aria-hidden="true" />{error}</p>}
        {retry && <div className="border-t border-(--line) px-5 py-3"><Button size="compact" disabled={busy} onClick={() => send(retry.text, retry.id)}>Retry last request</Button></div>}
        <ChatNotice>
          <p className="m-0">{ASSISTANT_SCOPE_NOTE}</p>
          <p className="m-0">{ASSISTANT_PROVIDER_NOTE}</p>
        </ChatNotice>
        <form className="grid gap-3 border-t border-(--line) px-5 py-4" onSubmit={event => { event.preventDefault(); void send(message); }}>
          <Textarea id="assistant-message" label="Ask about the selected client" value={message} maxLength={4000} rows={3} disabled={busy || !clientId}
            onChange={event => setMessage(event.target.value)} placeholder="Which endpoints are offline?" />
          <div className="flex flex-wrap items-center justify-between gap-3">
            <small className="text-xs text-(--muted)">{message.length}/4,000 · Avoid entering secrets or personal information.</small>
            {busy ? <Button onClick={() => cancel()}>Cancel</Button> : <Button type="submit" variant="primary" disabled={!clientId || !message.trim()}>Send</Button>}
          </div>
        </form>
      </ChatCard>
    </ChatPanes>
  </PageStack>;
}
