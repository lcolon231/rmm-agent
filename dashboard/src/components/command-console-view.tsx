// SPDX-License-Identifier: AGPL-3.0-only

import {
  ArrowLeft,
  ChevronLeft,
  ChevronRight,
  Info,
  ScrollText,
  TerminalSquare,
  TriangleAlert,
} from "lucide-react";
import Link from "next/link";

import { CommandAutoRefresh } from "@/components/command-auto-refresh";
import { CommandDispatchForm } from "@/components/command-dispatch-form";
import type { DashboardOperator } from "@/lib/dashboard-auth-core";
import type { EndpointDetailData } from "@/lib/endpoint-detail";
import {
  commandDetailRequiresAdmin,
  commandKindDefinitions,
  commandPageCount,
  describeCommandStatus,
  hasActiveCommands,
  type CommandHistoryData,
  type CommandHistoryItem,
} from "@/lib/command-console-core";
import { formatEndpointDateTime } from "@/lib/endpoint-detail-core";
import type { MaintenanceWindow } from "@/lib/maintenance-windows-core";

function NodeLinkMark() {
  return (
    <span className="brand-mark" aria-hidden="true">
      <span />
      <span />
      <span />
    </span>
  );
}

function kindLabel(item: CommandHistoryItem): string {
  return commandKindDefinitions.find((d) => d.kind === item.kind)?.label ?? item.kind;
}

function StatusChip({ item }: { item: CommandHistoryItem }) {
  const presentation = describeCommandStatus(item.status);
  return <span className={`command-status ${presentation.tone}`}>{presentation.label}</span>;
}

function HistoryRow({
  endpointId,
  item,
  isAdmin,
}: {
  endpointId: string;
  item: CommandHistoryItem;
  isAdmin: boolean;
}) {
  const truncated = item.stdout_truncated === true || item.stderr_truncated === true;
  return (
    <tr>
      <td>
        {commandDetailRequiresAdmin(item.kind) && !isAdmin ? (
          <span title="Administrator access is required for remediation payloads and results.">
            {kindLabel(item)}
          </span>
        ) : (
          <Link href={`/endpoints/${encodeURIComponent(endpointId)}/commands/${encodeURIComponent(item.id)}`}>
            {kindLabel(item)}
          </Link>
        )}
      </td>
      <td><StatusChip item={item} /></td>
      <td>{item.exit_code === null ? "—" : item.exit_code}</td>
      <td>{truncated ? "Truncated" : ""}</td>
      <td>{formatEndpointDateTime(item.created_at)}</td>
      <td>{formatEndpointDateTime(item.completed_at)}</td>
      <td><code>{item.envelope_version}</code></td>
    </tr>
  );
}

export function CommandConsoleView({
  endpoint,
  history,
  operator,
  maintenanceWindows,
  serverNowMs,
}: {
  endpoint: EndpointDetailData;
  history: CommandHistoryData;
  operator: DashboardOperator;
  /** Null when the window inventory could not be verified. */
  maintenanceWindows: MaintenanceWindow[] | null;
  serverNowMs: number;
}) {
  const canDispatch = operator.role === "operator" || operator.role === "admin";
  const canExecuteScripts = endpoint.script_execution_allowed;
  const trusted = endpoint.trust_state === "active";
  const queueFull = history.outstanding >= history.outstanding_limit;
  const pageCount = commandPageCount(history.total, history.page_size);
  const basePath = `/endpoints/${encodeURIComponent(endpoint.id)}/commands`;

  return (
    <main className="endpoint-detail-page">
      {hasActiveCommands(history.items) ? <CommandAutoRefresh /> : null}
      <header className="detail-topbar">
        <Link className="detail-brand" href="/"><NodeLinkMark /><strong>NodeLink</strong></Link>
        <span className="detail-context">Command console</span>
        <div className="detail-operator"><span>{operator.email}</span><small>{operator.role}</small></div>
      </header>

      <div className="detail-workspace">
        <nav className="detail-breadcrumbs" aria-label="Breadcrumb">
          <Link href={`/endpoints/${encodeURIComponent(endpoint.id)}`}><ArrowLeft size={15} /> {endpoint.hostname}</Link>
          <span>/</span><span>{endpoint.client_name}</span><span>/</span><span>{endpoint.site_name}</span><span>/</span><span>Commands</span>
        </nav>

        <section className="detail-identity" aria-labelledby="console-title">
          <div className="detail-device-mark"><TerminalSquare size={28} /></div>
          <div className="detail-title">
            <span className="eyebrow">Command console</span>
            <h1 id="console-title">{endpoint.hostname}</h1>
            <p>Every command is signed, expires on schedule, and is written to the tamper-evident audit log with your operator identity.</p>
          </div>
          <div className="detail-state-stack">
            <span className={`detail-status ${endpoint.status}`}>{endpoint.status === "online" ? "Online" : endpoint.status === "offline" ? "Offline" : "Pending first heartbeat"}</span>
            <span className={`command-queue-meter ${queueFull ? "full" : ""}`}>Queue {history.outstanding}/{history.outstanding_limit}</span>
          </div>
        </section>

        {!trusted ? (
          <section className="detail-notice stale" role="status">
            <TriangleAlert size={19} />
            <div>
              <strong>Dispatch is blocked: this endpoint is {endpoint.trust_state}</strong>
              <span>Restore the endpoint&apos;s trust state before queueing new work. History remains available below.</span>
            </div>
          </section>
        ) : null}

        {canDispatch && trusted ? (
          <section className="command-dispatch-panel" aria-labelledby="dispatch-title">
            <header>
              <div><span className="eyebrow">New command</span><h2 id="dispatch-title">Dispatch to this endpoint</h2></div>
            </header>
            {queueFull ? (
              <p className="dispatch-queue-warning" role="status">
                The queue is at its {history.outstanding_limit}-command admission limit. New dispatches
                will be refused until pending commands finish or expire.
              </p>
            ) : null}
            {!canExecuteScripts ? (
              <p className="dispatch-queue-warning" role="status">
                Arbitrary PowerShell and shell execution is default-denied for this endpoint.
                An administrator must grant your operator an explicit matching scope. Typed
                inventory collection remains available.
              </p>
            ) : null}
            <p className="command-update-route-note">
              Windows Update installs are selected from the endpoint&apos;s current scan inventory so
              a normal install can never mean “install everything.”{" "}
              <Link href={`/endpoints/${encodeURIComponent(endpoint.id)}/inventory#windows-updates`}>
                Select Windows updates
              </Link>
            </p>
            <CommandDispatchForm
              canExecuteScripts={canExecuteScripts}
              endpointId={endpoint.id}
              hostname={endpoint.hostname}
              isAdmin={operator.role === "admin"}
              maintenanceTarget={{
                agentId: endpoint.id,
                siteId: endpoint.site_id,
                clientId: endpoint.client_id,
              }}
              maintenanceWindows={maintenanceWindows}
              serverNowMs={serverNowMs}
            />
          </section>
        ) : null}

        {!canDispatch ? (
          <section className="detail-notice unavailable" role="status">
            <Info size={19} />
            <div>
              <strong>Read-only access</strong>
              <span>Your role can review command history and results, but dispatching requires the operator role.</span>
            </div>
          </section>
        ) : null}

        <section className="command-history" aria-labelledby="history-title">
          <header>
            <div><span className="eyebrow">Signed command record</span><h2 id="history-title">Command history</h2><p>Newest first. Open a command for its envelope evidence and captured output.</p></div>
            <span className="command-history-count"><ScrollText size={15} /> {history.total} total</span>
          </header>
          {history.items.length ? (
            <div className="command-history-scroll">
              <table>
                <thead>
                  <tr><th>Command</th><th>Status</th><th>Exit code</th><th>Capture</th><th>Created</th><th>Completed</th><th>Envelope</th></tr>
                </thead>
                <tbody>
                  {history.items.map((item) => (
                    <HistoryRow
                      endpointId={endpoint.id}
                      isAdmin={operator.role === "admin"}
                      item={item}
                      key={item.id}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="detail-empty"><TerminalSquare size={24} /><strong>No commands yet</strong><span>Commands dispatched to this endpoint will appear here with their full signed record.</span></div>
          )}
          {pageCount > 1 ? (
            <nav className="command-pagination" aria-label="Command history pages">
              {history.page > 1 ? <Link href={`${basePath}?page=${history.page - 1}`}><ChevronLeft size={15} /> Newer</Link> : <span />}
              <span>Page {history.page} of {pageCount}</span>
              {history.page < pageCount ? <Link href={`${basePath}?page=${history.page + 1}`}>Older <ChevronRight size={15} /></Link> : <span />}
            </nav>
          ) : null}
        </section>

        <footer className="detail-footer"><span>Endpoint ID <code>{endpoint.id}</code></span><span>Commands cannot be cancelled after dispatch; unpicked work dies at its signed expiry.</span></footer>
      </div>
    </main>
  );
}
