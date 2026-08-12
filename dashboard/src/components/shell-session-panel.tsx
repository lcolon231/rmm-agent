// SPDX-License-Identifier: AGPL-3.0-only
"use client";

import { CircleStop, LoaderCircle, Play, Send, TerminalSquare } from "lucide-react";
import { FormEvent, useEffect, useRef, useState } from "react";

import {
  describeShellSessionAvailability,
  shellFrameBatchFromUnknown,
  shellSessionFromUnknown,
  shellSessionStatePresentation,
  type ShellSessionData,
} from "@/lib/shell-session-core";

type TerminalLine = { id: string; stream: "input" | "stdout" | "stderr" | "control"; text: string };
const MAX_VISIBLE_CHARS = 256 * 1024;

function encodeBase64(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function decodeBase64(value: string): string {
  const binary = atob(value);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

export function ShellSessionPanel({ endpointId, trusted, capable, canExecuteScripts }: {
  endpointId: string;
  trusted: boolean;
  capable: boolean;
  canExecuteScripts: boolean;
}) {
  const availability = describeShellSessionAvailability({ trusted, capable, canExecuteScripts });
  const [session, setSession] = useState<ShellSessionData | null>(null);
  const [lines, setLines] = useState<TerminalLine[]>([]);
  const [command, setCommand] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const outputSeq = useRef(0);
  const inputSeq = useRef(0);
  const terminal = useRef<HTMLDivElement>(null);

  useEffect(() => {
    terminal.current?.scrollTo({ top: terminal.current.scrollHeight });
  }, [lines]);

  useEffect(() => {
    if (!session || ["closed", "denied", "timed_out", "failed"].includes(session.status)) return;
    const controller = new AbortController();
    let stopped = false;
    const poll = async () => {
      while (!stopped) {
        try {
          const response = await fetch(`/api/endpoints/${encodeURIComponent(endpointId)}/shell-sessions/${encodeURIComponent(session.id)}/output?after=${outputSeq.current}&ack=${outputSeq.current}`, { cache: "no-store", signal: controller.signal });
          const raw: unknown = await response.json();
          if (!response.ok) {
            if (response.status >= 500) {
              await new Promise((resolve) => window.setTimeout(resolve, 1000));
              continue;
            }
            throw new Error(typeof raw === "object" && raw !== null && typeof (raw as { error?: unknown }).error === "string" ? String((raw as { error: string }).error) : "Live output stopped.");
          }
          const batch = shellFrameBatchFromUnknown(raw);
          if (!batch) throw new Error("The server returned invalid live output.");
          setError(null);
          setSession(batch.session);
          if (batch.frames.length) {
            setLines((current) => {
              const next = [...current, ...batch.frames.map((frame) => ({ id: `${frame.seq}-${frame.stream}`, stream: frame.stream, text: decodeBase64(frame.data_b64) } as TerminalLine))];
              let total = next.reduce((sum, line) => sum + line.text.length, 0);
              while (next.length > 1 && total > MAX_VISIBLE_CHARS) total -= next.shift()!.text.length;
              return next;
            });
            outputSeq.current = batch.frames.at(-1)!.seq;
          }
          if (["closed", "denied", "timed_out", "failed"].includes(batch.session.status)) stopped = true;
        } catch (pollError) {
          if (!controller.signal.aborted) {
            // Browser/network interruptions keep the cursor and reconnect to
            // the same long poll. Validation and 4xx errors take the explicit
            // fail-closed path above.
            await new Promise((resolve) => window.setTimeout(resolve, 1000));
            if (!controller.signal.aborted) setError("Connection interrupted. Reconnecting…");
          }
        }
      }
    };
    void poll();
    return () => { stopped = true; controller.abort(); };
  }, [endpointId, session?.id, session?.status]);

  async function openSession() {
    setBusy(true); setError(null); setLines([]); outputSeq.current = 0; inputSeq.current = 0;
    try {
      const response = await fetch(`/api/endpoints/${encodeURIComponent(endpointId)}/shell-sessions`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
      const raw: unknown = await response.json();
      const parsed = typeof raw === "object" && raw !== null ? shellSessionFromUnknown((raw as { session?: unknown }).session) : null;
      if (!response.ok || !parsed) throw new Error(typeof raw === "object" && raw !== null && typeof (raw as { error?: unknown }).error === "string" ? String((raw as { error: string }).error) : "The shell could not be opened.");
      inputSeq.current = parsed.client_last_seq;
      if (parsed.status === "active") {
        outputSeq.current = parsed.agent_last_seq;
        setLines([{ id: "reconnected", stream: "control", text: "Reconnected to the active shell. New output will appear here.\n" }]);
      }
      setSession(parsed);
    } catch (openError) { setError(openError instanceof Error ? openError.message : "The shell could not be opened."); }
    finally { setBusy(false); }
  }

  async function sendCommand(event: FormEvent) {
    event.preventDefault();
    if (!session || session.status !== "active" || !command.trim()) return;
    const text = command.endsWith("\n") ? command : `${command}\n`;
    const nextSeq = inputSeq.current + 1;
    setBusy(true); setError(null);
    try {
      const response = await fetch(`/api/endpoints/${encodeURIComponent(endpointId)}/shell-sessions/${encodeURIComponent(session.id)}/input`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ seq: nextSeq, data_b64: encodeBase64(text) }) });
      const raw: unknown = await response.json();
      if (!response.ok) throw new Error(typeof raw === "object" && raw !== null && typeof (raw as { error?: unknown }).error === "string" ? String((raw as { error: string }).error) : "The command could not be sent.");
      inputSeq.current = nextSeq;
      setLines((current) => [...current, { id: `input-${nextSeq}`, stream: "input", text: `PS> ${command}\n` }]);
      setCommand("");
    } catch (sendError) { setError(sendError instanceof Error ? sendError.message : "The command could not be sent."); }
    finally { setBusy(false); }
  }

  async function closeSession() {
    if (!session) return;
    setBusy(true); setError(null);
    try {
      const response = await fetch(`/api/endpoints/${encodeURIComponent(endpointId)}/shell-sessions/${encodeURIComponent(session.id)}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
      const raw: unknown = await response.json();
      const parsed = typeof raw === "object" && raw !== null ? shellSessionFromUnknown((raw as { session?: unknown }).session) : null;
      if (!response.ok || !parsed) throw new Error("The shell could not be closed.");
      setSession(parsed);
    } catch (closeError) { setError(closeError instanceof Error ? closeError.message : "The shell could not be closed."); }
    finally { setBusy(false); }
  }

  const state = session ? shellSessionStatePresentation(session.status) : null;
  return (
    <section className="shell-panel" aria-labelledby="live-shell-title">
      <header>
        <div><span className="eyebrow"><TerminalSquare size={13} /> Live operations</span><h2 id="live-shell-title">Interactive PowerShell</h2><p>Output streams as it arrives. Session input and output are never stored.</p></div>
        <div className="shell-actions">
          {state ? <span className={`shell-state ${state.tone}`}>{state.label}</span> : null}
          {!session || state?.terminal ? <button type="button" disabled={!availability.canOpen || busy} onClick={openSession}>{busy ? <LoaderCircle className="spin" size={15} /> : <Play size={15} />} Open shell</button> : <button className="danger" type="button" disabled={busy} onClick={closeSession}><CircleStop size={15} /> Close shell</button>}
        </div>
      </header>
      {!availability.canOpen && !session ? <div className="shell-unavailable">{availability.reason}</div> : null}
      {session ? <>
        <div className="shell-screen" ref={terminal} role="log" aria-live="polite" aria-label="Live shell output">
          {lines.length ? lines.map((line) => <span className={line.stream} key={line.id}>{line.text}</span>) : <span className="control">{session.status === "pending" ? "Waiting for the endpoint to attach…" : "PowerShell connected. Enter a command below.\n"}</span>}
        </div>
        <form className="shell-input" onSubmit={sendCommand}>
          <label htmlFor="shell-command">PS&gt;</label><input id="shell-command" autoComplete="off" disabled={busy || session.status !== "active"} maxLength={12_000} onChange={(event) => setCommand(event.target.value)} placeholder={session.status === "active" ? "Get-Process | Select-Object -First 10" : "Waiting for a live connection"} spellCheck={false} value={command} /><button type="submit" disabled={busy || session.status !== "active" || !command.trim()}><Send size={15} /><span>Run</span></button>
        </form>
        <footer><span>{session.output_bytes_total.toLocaleString()} / {(session.output_bytes_limit ?? 0).toLocaleString()} output bytes</span><span>{session.frames_out} output frames</span></footer>
      </> : null}
      {error ? <p className="shell-error" role="alert">{error}</p> : null}
    </section>
  );
}
