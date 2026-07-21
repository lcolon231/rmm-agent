// SPDX-License-Identifier: AGPL-3.0-only

import { ArrowLeft, FileSignature, TerminalSquare } from "lucide-react";
import Link from "next/link";

import { CommandAutoRefresh } from "@/components/command-auto-refresh";
import type { DashboardOperator } from "@/lib/dashboard-auth-core";
import type { EndpointDetailData } from "@/lib/endpoint-detail";
import {
  commandKindDefinitions,
  describeCommandStatus,
  describeStreamCapture,
  formatByteCount,
  type CommandDetailData,
  type StreamName,
} from "@/lib/command-console-core";
import { formatEndpointDateTime } from "@/lib/endpoint-detail-core";

function NodeLinkMark() {
  return (
    <span className="brand-mark" aria-hidden="true">
      <span />
      <span />
      <span />
    </span>
  );
}

function OutputStream({
  command,
  stream,
}: {
  command: CommandDetailData;
  stream: StreamName;
}) {
  const text = stream === "stdout" ? command.stdout : command.stderr;
  const truncated = stream === "stdout" ? command.stdout_truncated : command.stderr_truncated;
  const totalBytes = stream === "stdout" ? command.stdout_total_bytes : command.stderr_total_bytes;
  const note = describeStreamCapture(truncated, totalBytes, text);

  return (
    <article className="command-stream">
      <header>
        <h3>{stream}</h3>
        <span className={truncated === true ? "truncated" : ""}>{note}</span>
      </header>
      {text ? (
        <pre tabIndex={0}>{text}</pre>
      ) : (
        <p className="command-stream-empty">No {stream} was stored for this command.</p>
      )}
    </article>
  );
}

function EnvelopeRow({ label, value }: { label: string; value: string | null }) {
  return (
    <div><dt>{label}</dt><dd>{value === null || value === "" ? "—" : <code>{value}</code>}</dd></div>
  );
}

export function CommandDetailView({
  command,
  endpoint,
  operator,
}: {
  command: CommandDetailData;
  endpoint: EndpointDetailData;
  operator: DashboardOperator;
}) {
  const presentation = describeCommandStatus(command.status);
  const kindLabel = commandKindDefinitions.find((d) => d.kind === command.kind)?.label ?? command.kind;
  const script = typeof command.payload.script === "string" ? command.payload.script : null;
  const hasResult = command.status === "succeeded" || command.status === "failed";

  return (
    <main className="endpoint-detail-page">
      {presentation.terminal ? null : <CommandAutoRefresh />}
      <header className="detail-topbar">
        <Link className="detail-brand" href="/"><NodeLinkMark /><strong>NodeLink</strong></Link>
        <span className="detail-context">Command record</span>
        <div className="detail-operator"><span>{operator.email}</span><small>{operator.role}</small></div>
      </header>

      <div className="detail-workspace">
        <nav className="detail-breadcrumbs" aria-label="Breadcrumb">
          <Link href={`/endpoints/${encodeURIComponent(endpoint.id)}/commands`}><ArrowLeft size={15} /> Command console</Link>
          <span>/</span><span>{endpoint.client_name}</span><span>/</span><span>{endpoint.hostname}</span>
        </nav>

        <section className="detail-identity" aria-labelledby="command-title">
          <div className="detail-device-mark"><TerminalSquare size={28} /></div>
          <div className="detail-title">
            <span className="eyebrow">{kindLabel} command</span>
            <h1 id="command-title">{endpoint.hostname}</h1>
            <p>Created {formatEndpointDateTime(command.created_at)} · Command ID <code>{command.id}</code></p>
          </div>
          <div className="detail-state-stack">
            <span className={`command-status ${presentation.tone}`}>{presentation.label}</span>
            {command.exit_code !== null ? <span className="command-exit">Exit code {command.exit_code}</span> : null}
          </div>
        </section>

        <section className="command-lifecycle" aria-label="Command lifecycle">
          <article><span>Created</span><strong>{formatEndpointDateTime(command.created_at)}</strong></article>
          <article><span>Dispatched to agent</span><strong>{formatEndpointDateTime(command.dispatched_at)}</strong></article>
          <article><span>Completed</span><strong>{formatEndpointDateTime(command.completed_at)}</strong></article>
          <article><span>Expires</span><strong>{formatEndpointDateTime(command.expires_at)}</strong></article>
        </section>

        {script !== null ? (
          <section className="command-payload" aria-labelledby="payload-title">
            <header><div><span className="eyebrow">Signed payload</span><h2 id="payload-title">Script</h2></div></header>
            <pre tabIndex={0}>{script}</pre>
          </section>
        ) : null}

        <section className="command-result" aria-labelledby="result-title">
          <header>
            <div><span className="eyebrow">Bounded capture</span><h2 id="result-title">Result</h2></div>
          </header>
          {hasResult ? (
            <>
              {command.stdout_truncated === true || command.stderr_truncated === true ? (
                <p className="command-truncation-banner" role="status">
                  Output was truncated at the agent&apos;s capture limit. The totals below record what
                  the command actually produced ({formatByteCount(command.stdout_total_bytes)} stdout,{" "}
                  {formatByteCount(command.stderr_total_bytes)} stderr); only the stored portion was kept.
                </p>
              ) : null}
              <OutputStream command={command} stream="stdout" />
              <OutputStream command={command} stream="stderr" />
            </>
          ) : (
            <div className="detail-empty">
              <TerminalSquare size={24} />
              <strong>{command.status === "expired" ? "No result: the command expired" : "No result yet"}</strong>
              <span>
                {command.status === "expired"
                  ? "The signed validity window closed before the agent completed this command."
                  : "The agent has not reported a result. This page refreshes automatically."}
              </span>
            </div>
          )}
        </section>

        <section className="command-envelope" aria-labelledby="envelope-title">
          <header><div><span className="eyebrow"><FileSignature size={14} /> Tamper-evident record</span><h2 id="envelope-title">Signed envelope</h2></div></header>
          <dl>
            <EnvelopeRow label="Envelope version" value={command.envelope_version} />
            <EnvelopeRow label="Schema version" value={command.schema_version === null ? null : String(command.schema_version)} />
            <EnvelopeRow label="Signing key" value={command.signing_key_id} />
            <EnvelopeRow label="Nonce" value={command.nonce} />
            <EnvelopeRow label="Issued at" value={command.issued_at} />
            <EnvelopeRow label="Expires at" value={command.expires_at} />
          </dl>
          <details>
            <summary>Ed25519 signature</summary>
            <code className="command-signature">{command.signature}</code>
          </details>
          <p>The dispatching operator and this command&apos;s full envelope hash are recorded in the audit log under command ID <code>{command.id}</code>.</p>
        </section>

        <footer className="detail-footer"><span>Endpoint ID <code>{endpoint.id}</code></span><span>Agent {endpoint.agent_version || "version unavailable"}</span></footer>
      </div>
    </main>
  );
}
