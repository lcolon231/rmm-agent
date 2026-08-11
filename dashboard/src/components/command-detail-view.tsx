// SPDX-License-Identifier: AGPL-3.0-only

import { AlertTriangle, ArrowLeft, CheckCircle2, FileSignature, RefreshCw, TerminalSquare } from "lucide-react";
import Link from "next/link";

import { CommandAutoRefresh } from "@/components/command-auto-refresh";
import type { DashboardOperator } from "@/lib/dashboard-auth-core";
import type { EndpointDetailData } from "@/lib/endpoint-detail";
import {
  commandKindDefinitions,
  describeCommandStatus,
  describeStreamCapture,
  eventLogQueryResultFromUnknown,
  formatByteCount,
  powerOperationResultFromUnknown,
  type CommandDetailData,
  type EventLogQueryResult,
  type PowerOperationResult,
  type StreamName,
} from "@/lib/command-console-core";
import { formatAgentVersion, formatEndpointDateTime } from "@/lib/endpoint-detail-core";
import {
  installUpdatesResultFromUnknown,
  type InstallUpdatesResultView,
} from "@/lib/windows-updates-core";

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

function UpdateInstallResult({
  endpointId,
  result,
}: {
  endpointId: string;
  result: InstallUpdatesResultView;
}) {
  const failed = result.status === "failed" || result.failedKBs.length > 0;
  return (
    <div className={`windows-update-command-result ${failed ? "failed" : "succeeded"}`}>
      <header>
        {failed ? <AlertTriangle aria-hidden="true" size={21} /> : <CheckCircle2 aria-hidden="true" size={21} />}
        <div>
          <strong>{result.message}</strong>
          <span>{result.rebootRequired ? "The endpoint reports that a restart is required." : "No restart requirement was reported."}</span>
        </div>
      </header>
      <div className="windows-update-result-columns">
        <section>
          <span>Installed · {result.installedKBs.length}</span>
          {result.installedKBs.length ? (
            <ul>{result.installedKBs.map((kbID) => <li key={kbID}><code>{kbID}</code></li>)}</ul>
          ) : <p>None reported.</p>}
        </section>
        <section className={result.failedKBs.length ? "failed" : ""}>
          <span>Failed · {result.failedKBs.length}</span>
          {result.failedKBs.length ? (
            <ul>{result.failedKBs.map((kbID) => <li key={kbID}><code>{kbID}</code></li>)}</ul>
          ) : <p>None reported.</p>}
        </section>
      </div>
      {result.reboot ? (
        <p className="windows-update-reboot-note">
          Reboot policy <code>{result.reboot.policy}</code> →{" "}
          <strong>{result.reboot.decision.replaceAll("_", " ")}</strong>
          {result.reboot.decision === "scheduled" && result.reboot.delaySeconds !== null
            ? ` in ${result.reboot.delaySeconds} seconds`
            : result.reboot.decision === "deferred_user_present"
              ? " — a user is signed in, so the reboot was held"
              : ""}
          .
        </p>
      ) : null}
      {result.results.some((outcome) => outcome.attempts > 1) ? (
        <p className="windows-update-reboot-note">
          Some updates were retried:{" "}
          {result.results
            .filter((outcome) => outcome.attempts > 1)
            .map((outcome) => `${outcome.identifier} (${outcome.attempts} attempts)`)
            .join(", ")}
          .
        </p>
      ) : null}
      <p className="windows-update-rescan-prompt">
        <RefreshCw aria-hidden="true" size={15} />
        Installation results do not refresh inventory automatically. Run a new scan to verify the endpoint&apos;s remaining updates.
        <Link href={`/endpoints/${encodeURIComponent(endpointId)}/commands`}>Open command console</Link>
      </p>
    </div>
  );
}

function PowerResult({ result }: { result: PowerOperationResult }) {
  const successful = ["scheduled", "cancelled", "none_pending"].includes(result.status);
  return (
    <div className={`power-command-result ${successful ? "succeeded" : "failed"}`}>
      <header>
        {successful ? <CheckCircle2 aria-hidden="true" size={21} /> : <AlertTriangle aria-hidden="true" size={21} />}
        <div>
          <strong>{result.message ?? result.status.replaceAll("_", " ")}</strong>
          <span>Endpoint status: {result.status.replaceAll("_", " ")}</span>
        </div>
      </header>
      <dl>
        <div><dt>Action</dt><dd>{result.action.replaceAll("_", " ")}</dd></div>
        <div><dt>Delay</dt><dd>{result.delaySeconds === null ? "Not applicable" : `${result.delaySeconds} seconds`}</dd></div>
        <div><dt>Maintenance window</dt><dd><code>{result.maintenanceWindowId ?? "Not required"}</code></dd></div>
        <div><dt>User policy</dt><dd>{result.userConsent?.replaceAll("_", " ") ?? "Not applicable"}</dd></div>
        <div><dt>Reason evidence</dt><dd><code>{result.reasonSHA256}</code></dd></div>
      </dl>
    </div>
  );
}

function EventLogResult({ result }: { result: EventLogQueryResult }) {
  const ok = result.status === "ok";
  return (
    <div className={`event-log-command-result ${ok ? "succeeded" : "failed"}`}>
      <header>
        {ok ? <CheckCircle2 aria-hidden="true" size={21} /> : <AlertTriangle aria-hidden="true" size={21} />}
        <div>
          <strong>{result.message ?? `${result.count} event${result.count === 1 ? "" : "s"} from ${result.channel}`}</strong>
          <span>
            Metadata only — no message text is collected.
            {result.hasMore ? ` More events are available; continue from cursor ${result.nextCursor}.` : ""}
          </span>
        </div>
      </header>
      {result.records.length ? (
        <table className="event-log-records">
          <thead>
            <tr><th>Record</th><th>Time</th><th>Provider</th><th>Event ID</th><th>Level</th></tr>
          </thead>
          <tbody>
            {result.records.map((record) => (
              <tr key={record.recordId}>
                <td><code>{record.recordId}</code></td>
                <td>{record.timeCreated ? formatEndpointDateTime(record.timeCreated) : "—"}</td>
                <td>{record.provider || "—"}</td>
                <td>{record.eventId}</td>
                <td>{record.level}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p>No matching events were returned within the bounded window.</p>
      )}
    </div>
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
  const updateInstallResult = command.kind === "install_updates"
    ? installUpdatesResultFromUnknown(command.stdout)
    : null;
  const updateTargets = command.kind === "install_updates"
    ? [
        ...(Array.isArray(command.payload.kb_ids) ? command.payload.kb_ids : []),
        ...(Array.isArray(command.payload.update_ids) ? command.payload.update_ids : []),
      ].filter((value): value is string => typeof value === "string")
    : [];
  const isPowerOperation = ["reboot", "shutdown", "cancel_power_action"].includes(command.kind);
  const powerResult = isPowerOperation ? powerOperationResultFromUnknown(command.stdout) : null;
  const eventLogResult = command.kind === "query_event_log"
    ? eventLogQueryResultFromUnknown(command.stdout)
    : null;

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
          <article><span>Finished on agent</span><strong>{formatEndpointDateTime(command.agent_completed_at)}</strong></article>
          <article><span>Result acknowledged</span><strong>{formatEndpointDateTime(command.completed_at)}</strong></article>
          <article><span>Expires</span><strong>{formatEndpointDateTime(command.expires_at)}</strong></article>
        </section>

        {script !== null ? (
          <section className="command-payload" aria-labelledby="payload-title">
            <header><div><span className="eyebrow">Signed payload</span><h2 id="payload-title">Script</h2></div></header>
            <pre tabIndex={0}>{script}</pre>
          </section>
        ) : command.kind === "install_updates" ? (
          <section className="command-payload" aria-labelledby="payload-title">
            <header><div><span className="eyebrow">Signed payload</span><h2 id="payload-title">Update targets</h2></div></header>
            <pre tabIndex={0}>
              {command.payload.install_all === true
                ? "All applicable non-hidden updates (explicit install_all)"
                : updateTargets.length
                  ? updateTargets.join("\n")
                  : "No update targets were recorded."}
            </pre>
          </section>
        ) : isPowerOperation ? (
          <section className="command-payload power-command-payload" aria-labelledby="payload-title">
            <header><div><span className="eyebrow">Signed safety policy</span><h2 id="payload-title">Power operation</h2></div></header>
            <dl>
              <div><dt>Action</dt><dd>{kindLabel}</dd></div>
              <div><dt>Reason</dt><dd>{typeof command.payload.reason === "string" ? command.payload.reason : "—"}</dd></div>
              <div><dt>Delay</dt><dd>{typeof command.payload.delay_seconds === "number" ? `${command.payload.delay_seconds} seconds` : "Not applicable"}</dd></div>
              <div><dt>User policy</dt><dd>{typeof command.payload.user_consent === "string" ? command.payload.user_consent.replaceAll("_", " ") : "Not applicable"}</dd></div>
              <div><dt>Maintenance window</dt><dd><code>{typeof command.payload.maintenance_window_id === "string" ? command.payload.maintenance_window_id : "Not required"}</code></dd></div>
              <div><dt>Window closes</dt><dd>{typeof command.payload.maintenance_window_ends_at === "string" ? formatEndpointDateTime(command.payload.maintenance_window_ends_at) : "Not applicable"}</dd></div>
            </dl>
          </section>
        ) : command.kind === "query_event_log" ? (
          <section className="command-payload" aria-labelledby="payload-title">
            <header><div><span className="eyebrow">Signed query</span><h2 id="payload-title">Event log query</h2></div></header>
            <dl>
              <div><dt>Channel</dt><dd>{typeof command.payload.channel === "string" ? command.payload.channel : "—"}</dd></div>
              <div><dt>Time window</dt><dd>{typeof command.payload.time_window_seconds === "number" ? `${command.payload.time_window_seconds} seconds` : "—"}</dd></div>
              <div><dt>Max events</dt><dd>{typeof command.payload.max_events === "number" ? command.payload.max_events : "—"}</dd></div>
              <div><dt>Providers</dt><dd>{Array.isArray(command.payload.providers) ? command.payload.providers.join(", ") : "Any"}</dd></div>
              <div><dt>Levels</dt><dd>{Array.isArray(command.payload.levels) ? command.payload.levels.join(", ") : "Any"}</dd></div>
              <div><dt>Event IDs</dt><dd>{Array.isArray(command.payload.event_ids) ? command.payload.event_ids.join(", ") : "Any"}</dd></div>
            </dl>
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
              {updateInstallResult ? (
                <>
                  <UpdateInstallResult endpointId={endpoint.id} result={updateInstallResult} />
                  {command.stderr ? <OutputStream command={command} stream="stderr" /> : null}
                </>
              ) : powerResult ? (
                <>
                  <PowerResult result={powerResult} />
                  {command.stderr ? <OutputStream command={command} stream="stderr" /> : null}
                </>
              ) : eventLogResult ? (
                <>
                  <EventLogResult result={eventLogResult} />
                  {command.stderr ? <OutputStream command={command} stream="stderr" /> : null}
                </>
              ) : (
                <>
                  <OutputStream command={command} stream="stdout" />
                  <OutputStream command={command} stream="stderr" />
                </>
              )}
            </>
          ) : (
            <div className="detail-empty">
              <TerminalSquare size={24} />
              <strong>
                {command.status === "expired"
                  ? "No result: the command expired"
                  : command.status === "result_pending"
                    ? "Execution finished; result delivery is pending"
                    : "No result yet"}
              </strong>
              <span>
                {command.status === "expired"
                  ? "The signed validity window closed before the agent completed this command."
                  : command.status === "result_pending"
                    ? "The endpoint durably retained the result and will retry until the server acknowledges it."
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

        <footer className="detail-footer"><span>Endpoint ID <code>{endpoint.id}</code></span><span>Agent {formatAgentVersion(endpoint.agent_version)}</span></footer>
      </div>
    </main>
  );
}
