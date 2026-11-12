// SPDX-License-Identifier: AGPL-3.0-only

import { CircleAlert, CircleCheck, Clock, Minus, RefreshCw } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { CommandAutoRefresh } from "@/components/command-auto-refresh";
import type { DashboardOperator } from "@/lib/dashboard-auth-core";
import type { EndpointDetailData } from "@/lib/endpoint-detail";
import {
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
import { custodySteps, type CustodyState } from "@/lib/endpoint-pages-core";
import { commandBadge } from "@/lib/endpoint-summary-core";
import {
  installUpdatesResultFromUnknown,
  type InstallUpdatesResultView,
} from "@/lib/windows-updates-core";

import { commandKindLabel } from "./endpoint/command-history-table";
import { endpointBase, endpointCrumbs, inlineLink, monoText, Notice, Panel } from "./endpoint/section-header";
import { PageHeader, PageStack } from "./shell/page-header";
import { cx } from "./ui/cx";
import { CodeBlock, DefinitionList } from "./ui/drawer";
import { StatusBadge, toneStyles, type StatusTone } from "./ui/status-badge";
import { TabNav } from "./ui/tab-nav";

export type CommandDetailTab = "output" | "custody" | "details";

function Mono({ children }: { children: ReactNode }) {
  return <span className={cx(monoText, "break-all")}>{children}</span>;
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
  const title = stream === "stdout" ? "Output (stdout)" : "Errors (stderr)";

  return (
    <Panel title={title} sub={<span className={truncated === true ? "font-semibold text-[#89500b]" : undefined}>{note}</span>}>
      <div className="p-4">
        {text ? (
          <CodeBlock label={title}>{text}</CodeBlock>
        ) : (
          <p className="m-0 text-sm text-(--muted)">No {stream} was stored for this command.</p>
        )}
      </div>
    </Panel>
  );
}

function IdList({ ids, staged }: { ids: string[]; staged?: Set<string> }) {
  if (!ids.length) return <p className="m-0 text-sm text-(--muted)">None reported.</p>;
  return (
    <ul className="m-0 grid list-none gap-1.5 p-0">
      {ids.map((kbID) => (
        <li key={kbID} className="flex flex-wrap items-center gap-2">
          <Mono>{kbID}</Mono>
          {staged?.has(kbID) ? <span className="rounded-full bg-(--amber-soft) px-2 py-0.5 text-xs font-semibold text-[#89500b]">pending restart</span> : null}
        </li>
      ))}
    </ul>
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
  // Succeeded updates that WUA flagged as pending a restart are only staged;
  // older agents omit the per-update flag, so the set is empty for them.
  const stagedKBs = new Set(
    result.results
      .filter((outcome) => outcome.resultCode === 2 && outcome.rebootRequired === true)
      .map((outcome) => outcome.identifier),
  );
  return (
    <Panel title="Update installation">
      <div className="grid gap-4 p-5">
        <Notice tone={failed ? "crit" : "ok"} title={result.message}>
          {result.rebootRequired
            ? stagedKBs.size
              ? `A restart is required to finish ${stagedKBs.size} of ${result.installedKBs.length} installed update(s).`
              : "The endpoint reports that a restart is required."
            : "No restart requirement was reported."}
        </Notice>
        <div className="grid gap-4 min-[640px]:grid-cols-2">
          <section aria-label="Installed updates" className="grid content-start gap-2">
            <h3 className="m-0 text-[13px] font-semibold text-(--slate)">Installed · {result.installedKBs.length}</h3>
            <IdList ids={result.installedKBs} staged={stagedKBs} />
          </section>
          <section aria-label="Failed updates" className="grid content-start gap-2">
            <h3 className={cx("m-0 text-[13px] font-semibold", result.failedKBs.length ? "text-(--red)" : "text-(--slate)")}>Failed · {result.failedKBs.length}</h3>
            <IdList ids={result.failedKBs} />
          </section>
        </div>
        {result.reboot ? (
          <p className="m-0 text-sm text-(--slate)">
            Reboot policy <Mono>{result.reboot.policy}</Mono> →{" "}
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
          <p className="m-0 text-sm text-(--slate)">
            Some updates were retried:{" "}
            {result.results
              .filter((outcome) => outcome.attempts > 1)
              .map((outcome) => `${outcome.identifier} (${outcome.attempts} attempts)`)
              .join(", ")}
            .
          </p>
        ) : null}
        <p className="m-0 flex flex-wrap items-center gap-2 text-sm text-(--slate)">
          <RefreshCw aria-hidden="true" size={15} />
          Installation results do not refresh inventory automatically. Run a new scan to verify the endpoint&apos;s remaining updates.
          <Link className={inlineLink} href={`/endpoints/${encodeURIComponent(endpointId)}/commands`}>Open command console</Link>
        </p>
      </div>
    </Panel>
  );
}

function PowerResult({ result }: { result: PowerOperationResult }) {
  const successful = ["scheduled", "cancelled", "none_pending"].includes(result.status);
  return (
    <Panel title="Power operation">
      <div className="grid gap-4 p-5">
        <Notice tone={successful ? "ok" : "crit"} title={result.message ?? result.status.replaceAll("_", " ")}>
          Endpoint status: {result.status.replaceAll("_", " ")}
        </Notice>
        <DefinitionList
          items={[
            { term: "Action", value: result.action.replaceAll("_", " ") },
            { term: "Delay", value: result.delaySeconds === null ? "Not applicable" : `${result.delaySeconds} seconds` },
            { term: "Maintenance window", value: <Mono>{result.maintenanceWindowId ?? "Not required"}</Mono> },
            { term: "User policy", value: result.userConsent?.replaceAll("_", " ") ?? "Not applicable" },
            { term: "Reason fingerprint", value: <Mono>{result.reasonSHA256}</Mono> },
          ]}
        />
      </div>
    </Panel>
  );
}

function EventLogResult({ result }: { result: EventLogQueryResult }) {
  const ok = result.status === "ok";
  return (
    <Panel title="Event log results">
      <div className="grid gap-4 p-5">
        <Notice tone={ok ? "ok" : "crit"} title={result.message ?? `${result.count} event${result.count === 1 ? "" : "s"} from ${result.channel}`}>
          Metadata only — no message text is collected.
          {result.hasMore ? ` More events are available; continue from cursor ${result.nextCursor}.` : ""}
        </Notice>
        {result.records.length ? (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[560px] border-collapse text-left text-[13px]">
              <caption className="sr-only">Returned events</caption>
              <thead className="bg-(--fog) text-xs text-(--muted)">
                <tr>
                  {["Record", "Time", "Provider", "Event ID", "Level"].map((heading) => (
                    <th key={heading} scope="col" className="px-3 py-2 font-semibold">{heading}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {result.records.map((record) => (
                  <tr key={record.recordId} className="border-t border-(--line) text-(--slate)">
                    <td className="px-3 py-1.5"><Mono>{record.recordId}</Mono></td>
                    <td className="px-3 py-1.5 whitespace-nowrap">{record.timeCreated ? formatEndpointDateTime(record.timeCreated) : "—"}</td>
                    <td className="px-3 py-1.5">{record.provider || "—"}</td>
                    <td className="px-3 py-1.5">{record.eventId}</td>
                    <td className="px-3 py-1.5">{record.level}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="m-0 text-sm text-(--muted)">No matching events were returned within the bounded window.</p>
        )}
      </div>
    </Panel>
  );
}

function ResultNote({ command }: { command: CommandDetailData }) {
  const exit = command.exit_code === null ? "" : ` Exit code ${command.exit_code}.`;
  switch (command.status) {
    case "succeeded":
      return <Notice tone="ok" title="Completed">{`The device reported success.${exit}`}</Notice>;
    case "failed":
      return <Notice tone="crit" role="alert" title="Failed">{`The device reported that the command did not succeed.${exit}`}</Notice>;
    case "expired":
      return <Notice tone="off" title="No result: the command expired">The signed validity window closed before the agent completed this command.</Notice>;
    case "result_pending":
      return <Notice tone="info" title="Execution finished; result delivery is pending">The endpoint durably retained the result and will retry until the server acknowledges it.</Notice>;
    default:
      return <Notice tone="info" title="No result yet">The agent has not reported a result. This page refreshes automatically.</Notice>;
  }
}

function OutputTab({ command, endpointId }: { command: CommandDetailData; endpointId: string }) {
  const hasResult = command.status === "succeeded" || command.status === "failed";
  const updateInstallResult = command.kind === "install_updates" ? installUpdatesResultFromUnknown(command.stdout) : null;
  const isPowerOperation = ["reboot", "shutdown", "cancel_power_action"].includes(command.kind);
  const powerResult = isPowerOperation ? powerOperationResultFromUnknown(command.stdout) : null;
  const eventLogResult = command.kind === "query_event_log" ? eventLogQueryResultFromUnknown(command.stdout) : null;
  const structured = updateInstallResult ? (
    <UpdateInstallResult endpointId={endpointId} result={updateInstallResult} />
  ) : powerResult ? (
    <PowerResult result={powerResult} />
  ) : eventLogResult ? (
    <EventLogResult result={eventLogResult} />
  ) : null;

  return (
    <div className="grid gap-6">
      <ResultNote command={command} />
      {hasResult ? (
        <>
          {command.stdout_truncated === true || command.stderr_truncated === true ? (
            <Notice tone="warn" title="Output was truncated at the agent's capture limit">
              The totals record what the command actually produced ({formatByteCount(command.stdout_total_bytes)} stdout,{" "}
              {formatByteCount(command.stderr_total_bytes)} stderr); only the stored portion was kept.
            </Notice>
          ) : null}
          {structured ? (
            <>
              {structured}
              {command.stderr ? <OutputStream command={command} stream="stderr" /> : null}
            </>
          ) : (
            <>
              <OutputStream command={command} stream="stdout" />
              <OutputStream command={command} stream="stderr" />
            </>
          )}
        </>
      ) : null}
    </div>
  );
}

const CUSTODY_TONE: Record<CustodyState, { tone: StatusTone; icon: typeof CircleCheck; word: string }> = {
  done: { tone: "ok", icon: CircleCheck, word: "Done" },
  failed: { tone: "crit", icon: CircleAlert, word: "Failed" },
  pending: { tone: "off", icon: Clock, word: "Not yet" },
  unknown: { tone: "off", icon: Minus, word: "Not recorded" },
  expired: { tone: "off", icon: Minus, word: "Expired" },
};

function CustodyTab({ command }: { command: CommandDetailData }) {
  const steps = custodySteps(command);
  return (
    <Panel title="Chain of custody" sub="Each step is marked done only when this command's record proves it.">
      <ol className="m-0 grid list-none gap-0 p-0" aria-label="Chain of custody steps">
        {steps.map((step) => {
          const style = CUSTODY_TONE[step.state];
          // Done and failed steps carry their tone; anything unproven stays neutral.
          const { surface, text } = toneStyles[style.tone];
          const Icon = style.icon;
          return (
            <li key={step.key} data-state={step.state} className="flex items-start gap-3 border-t border-(--line) px-5 py-3 first:border-t-0">
              <span className={cx("mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full", surface, text)}>
                <Icon size={14} aria-hidden="true" />
              </span>
              <span className="grid min-w-0 flex-1 gap-0.5">
                <span className="font-semibold text-(--ink)">
                  {step.label}
                  <span className="sr-only"> ({style.word})</span>
                </span>
                <span className="text-xs text-(--muted)">{step.detail}</span>
              </span>
              <span className="shrink-0 text-xs whitespace-nowrap text-(--muted)">{step.at ? formatEndpointDateTime(step.at) : "—"}</span>
            </li>
          );
        })}
      </ol>
      <p className="m-0 border-t border-(--line) px-5 py-3 text-xs text-(--muted)">
        Who sent it, any approval it needed, and its audit entry are not part of this record, so they are not shown as steps. The audit log keeps them under command ID{" "}
        <span className="font-(family-name:--font-data)">{command.id}</span>.
      </p>
    </Panel>
  );
}

function PayloadBlock({ command }: { command: CommandDetailData }) {
  const script = typeof command.payload.script === "string" ? command.payload.script : null;
  const isPowerOperation = ["reboot", "shutdown", "cancel_power_action"].includes(command.kind);
  const kindLabel = commandKindLabel(command.kind);
  if (script !== null) {
    return (
      <Panel title="Script" sub="Signed payload">
        <div className="p-4"><CodeBlock label="Script">{script}</CodeBlock></div>
      </Panel>
    );
  }
  if (command.kind === "install_updates") {
    const updateTargets = [
      ...(Array.isArray(command.payload.kb_ids) ? command.payload.kb_ids : []),
      ...(Array.isArray(command.payload.update_ids) ? command.payload.update_ids : []),
    ].filter((value): value is string => typeof value === "string");
    return (
      <Panel title="Update targets" sub="Signed payload">
        <div className="p-4">
          <CodeBlock label="Update targets">
            {command.payload.install_all === true
              ? "All applicable non-hidden updates (explicit install_all)"
              : updateTargets.length
                ? updateTargets.join("\n")
                : "No update targets were recorded."}
          </CodeBlock>
        </div>
      </Panel>
    );
  }
  if (isPowerOperation) {
    return (
      <Panel title="Power operation" sub="Signed safety policy">
        <div className="px-5 py-4">
          <DefinitionList
            items={[
              { term: "Action", value: kindLabel },
              { term: "Reason", value: typeof command.payload.reason === "string" ? command.payload.reason : "—" },
              { term: "Delay", value: typeof command.payload.delay_seconds === "number" ? `${command.payload.delay_seconds} seconds` : "Not applicable" },
              { term: "User policy", value: typeof command.payload.user_consent === "string" ? command.payload.user_consent.replaceAll("_", " ") : "Not applicable" },
              { term: "Maintenance window", value: <Mono>{typeof command.payload.maintenance_window_id === "string" ? command.payload.maintenance_window_id : "Not required"}</Mono> },
              { term: "Window closes", value: typeof command.payload.maintenance_window_ends_at === "string" ? formatEndpointDateTime(command.payload.maintenance_window_ends_at) : "Not applicable" },
            ]}
          />
        </div>
      </Panel>
    );
  }
  if (command.kind === "query_event_log") {
    return (
      <Panel title="Event log query" sub="Signed query">
        <div className="px-5 py-4">
          <DefinitionList
            items={[
              { term: "Channel", value: typeof command.payload.channel === "string" ? command.payload.channel : "—" },
              { term: "Time window", value: typeof command.payload.time_window_seconds === "number" ? `${command.payload.time_window_seconds} seconds` : "—" },
              { term: "Max events", value: typeof command.payload.max_events === "number" ? command.payload.max_events : "—" },
              { term: "Providers", value: Array.isArray(command.payload.providers) ? command.payload.providers.join(", ") : "Any" },
              { term: "Levels", value: Array.isArray(command.payload.levels) ? command.payload.levels.join(", ") : "Any" },
              { term: "Event IDs", value: Array.isArray(command.payload.event_ids) ? command.payload.event_ids.join(", ") : "Any" },
            ]}
          />
        </div>
      </Panel>
    );
  }
  return null;
}

function orDash(value: string | null) {
  return value === null || value === "" ? "—" : <Mono>{value}</Mono>;
}

function DetailsTab({ command }: { command: CommandDetailData }) {
  return (
    <div className="grid gap-6">
      <PayloadBlock command={command} />
      <Panel title="Signed envelope" sub="What the device checks before it runs anything">
        <div className="grid gap-4 px-5 py-4">
          <DefinitionList
            items={[
              { term: "Envelope version", value: orDash(command.envelope_version) },
              { term: "Schema version", value: orDash(command.schema_version === null ? null : String(command.schema_version)) },
              { term: "Signing key", value: orDash(command.signing_key_id) },
              { term: "Nonce", value: orDash(command.nonce) },
              { term: "Issued at", value: orDash(command.issued_at) },
              { term: "Expires at", value: orDash(command.expires_at) },
            ]}
          />
          <details>
            <summary className="cursor-pointer text-sm font-semibold text-(--primary-strong)">Ed25519 signature</summary>
            <div className="mt-3">
              <CodeBlock label="Ed25519 signature">{command.signature || "No signature recorded."}</CodeBlock>
            </div>
          </details>
          <p className="m-0 text-xs text-(--muted)">
            The dispatching operator and this command&apos;s full envelope fingerprint are recorded in the audit log under command ID{" "}
            <span className="font-(family-name:--font-data)">{command.id}</span>.
          </p>
        </div>
      </Panel>
    </div>
  );
}

/** "Who did what, and when", limited to the times this record actually holds. */
function RecordPanel({ command }: { command: CommandDetailData }) {
  const rows = [
    { action: "Record created", at: command.created_at },
    { action: "Envelope issued", at: command.issued_at },
    { action: "Sent to the device", at: command.dispatched_at },
    { action: "Device finished", at: command.agent_completed_at },
    { action: "Result stored", at: command.completed_at },
  ].filter((row): row is { action: string; at: string } => row.at !== null);
  return (
    <Panel title="Record" sub="Who did what, and when">
      <ul className="m-0 grid list-none gap-0 p-0" aria-label="Record times">
        {rows.map((row) => (
          <li key={row.action} className="flex items-baseline justify-between gap-3 border-t border-(--line) px-5 py-2.5 text-[13px] first:border-t-0">
            <span className="text-(--slate)">{row.action}</span>
            <span className="text-xs whitespace-nowrap text-(--muted)">{formatEndpointDateTime(row.at)}</span>
          </li>
        ))}
      </ul>
      <p className="m-0 border-t border-(--line) px-5 py-3 text-xs text-(--muted)">
        Who sent this command is kept in the audit log, not on this record.
      </p>
    </Panel>
  );
}

export function CommandDetailView({
  command,
  endpoint,
  tab = "output",
}: {
  command: CommandDetailData;
  endpoint: EndpointDetailData;
  operator: DashboardOperator;
  tab?: CommandDetailTab;
}) {
  const presentation = describeCommandStatus(command.status);
  const badge = commandBadge(command.status);
  const kindLabel = commandKindLabel(command.kind);
  const commandsHref = `${endpointBase(endpoint.id)}/commands`;
  const base = `${commandsHref}/${encodeURIComponent(command.id)}`;

  return (
    <PageStack>
      {presentation.terminal ? null : <CommandAutoRefresh />}
      <PageHeader
        breadcrumb={[...endpointCrumbs(endpoint.id, endpoint.hostname), { label: "Commands", href: commandsHref }, { label: kindLabel }]}
        title={kindLabel}
        status={<StatusBadge tone={badge.tone}>{badge.label}</StatusBadge>}
        description={
          <>
            A signed instruction for <span className="font-(family-name:--font-data)">{endpoint.hostname}</span>. Created {formatEndpointDateTime(command.created_at)}.
          </>
        }
      />
      <TabNav
        label="Command record"
        tabs={[
          { label: "Output", href: base, current: tab === "output" },
          { label: "Chain of custody", href: `${base}?tab=custody`, current: tab === "custody" },
          { label: "Details", href: `${base}?tab=details`, current: tab === "details" },
        ]}
      />
      <div className="grid items-start gap-6 min-[1100px]:grid-cols-[minmax(0,2fr)_minmax(280px,1fr)]">
        <div className="grid min-w-0 gap-6">
          {tab === "custody" ? <CustodyTab command={command} /> : tab === "details" ? <DetailsTab command={command} /> : <OutputTab command={command} endpointId={endpoint.id} />}
        </div>
        <div className="grid min-w-0 gap-6">
        <Panel title="At a glance">
          <div className="px-5 py-4">
            <DefinitionList
              items={[
                { term: "Device", value: <Link href={endpointBase(endpoint.id)} className={cx(inlineLink, "font-(family-name:--font-data)")}>{endpoint.hostname}</Link> },
                { term: "Command", value: kindLabel },
                { term: "Status", value: <StatusBadge tone={badge.tone}>{badge.label}</StatusBadge> },
                { term: "Exit code", value: command.exit_code === null ? "—" : <Mono>{String(command.exit_code)}</Mono> },
                { term: "Created", value: formatEndpointDateTime(command.created_at) },
                { term: "Valid until", value: formatEndpointDateTime(command.expires_at) },
                { term: "Command ID", value: <Mono>{command.id}</Mono> },
                { term: "Agent version", value: formatAgentVersion(endpoint.agent_version) },
              ]}
            />
          </div>
        </Panel>
        <RecordPanel command={command} />
        </div>
      </div>
    </PageStack>
  );
}
