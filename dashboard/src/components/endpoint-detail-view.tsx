// SPDX-License-Identifier: AGPL-3.0-only

import { Bot, ChevronRight, Cpu, HardDrive, MemoryStick, TerminalSquare, type LucideIcon } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { RemoteDesktopPanel } from "@/components/remote-desktop-panel";
import { ShellSessionPanel } from "@/components/shell-session-panel";
import { SupportChatLaunchButton } from "@/components/support-chat-launch-button";
import { commandKindDefinitions, type CommandHistoryItem } from "@/lib/command-console-core";
import type { DashboardOperator } from "@/lib/dashboard-auth-core";
import { formatSeen, type DeviceStatus } from "@/lib/device-status-core";
import type { EndpointDetailData } from "@/lib/endpoint-detail";
import { formatAgentVersion, formatEndpointDateTime, formatEndpointMetric, formatEndpointUptime } from "@/lib/endpoint-detail-core";
import { commandBadge, formatHistoryWindow, readingRange, TRUST_LABELS, type ReadingKey } from "@/lib/endpoint-summary-core";
import { SHELL_SESSION_CAPABILITY } from "@/lib/shell-session-core";

import { PageHeader, PageStack } from "./shell/page-header";
import { ButtonLink } from "./ui/button";
import { cx, focusRing } from "./ui/cx";
import { DefinitionList } from "./ui/drawer";
import { meterLevel } from "./ui/meter";
import { cardClass } from "./ui/stat-tile";
import { StatusBadge, toneStyles, type StatusTone } from "./ui/status-badge";
import { TabNav } from "./ui/tab-nav";

export type EndpointDetailTab = "summary" | "remote";

type EndpointDetailViewProps = {
  endpoint: EndpointDetailData;
  operator: DashboardOperator;
  status: DeviceStatus;
  /** null when command history could not be loaded. */
  commands: CommandHistoryItem[] | null;
  tab: EndpointDetailTab;
  now: string;
};

const READINGS: Array<{ key: ReadingKey; label: string; icon: LucideIcon }> = [
  { key: "cpu_percent", label: "Processor", icon: Cpu },
  { key: "mem_percent", label: "Memory", icon: MemoryStick },
  { key: "disk_percent", label: "Disk", icon: HardDrive },
];

const RANGES = [6, 24, 72, 168];

const ADVICE: Partial<Record<StatusTone, string>> = {
  crit: "Open the alert to see what was measured, then decide on a fix.",
  off: "Check the device is switched on and connected; it reports again as soon as it is back.",
  warn: "Keep an eye on it. If the reading stays high, free up space or close heavy programs.",
};

const PIE_FILL = { normal: "var(--primary-on-dark)", warn: "var(--amber)", crit: "var(--red)" } as const;

function Card({ title, sub, action, children }: { title: string; sub?: ReactNode; action?: ReactNode; children: ReactNode }) {
  return (
    <section aria-label={title} className={cx(cardClass, "overflow-hidden")}>
      <header className="flex flex-wrap items-start justify-between gap-3 border-b border-(--line) px-5 py-4">
        <div className="grid gap-0.5">
          <h2 className="m-0 text-base font-semibold text-(--ink)">{title}</h2>
          {sub ? <p className="m-0 text-xs text-(--muted)">{sub}</p> : null}
        </div>
        {action}
      </header>
      {children}
    </section>
  );
}

function Pie({ label, icon: Icon, value, low, high, window }: { label: string; icon: LucideIcon; value: number | null; low: number | null; high: number | null; window: string }) {
  const percent = value === null ? null : Math.min(100, Math.max(0, Math.round(value)));
  const fill = percent === null ? null : PIE_FILL[meterLevel(percent)];
  return (
    <figure className="m-0 grid justify-items-center gap-2 text-center">
      <figcaption className="flex items-center gap-1.5 text-[13px] font-semibold text-(--slate)">
        <Icon size={16} aria-hidden="true" />
        {label}
      </figcaption>
      <div
        role="img"
        aria-label={percent === null ? `${label}: no reading` : `${label}: ${percent}% in use`}
        className="relative size-[120px] rounded-full"
        style={{ background: fill === null ? "#ece9f5" : `conic-gradient(${fill} 0 ${percent}%, #ece9f5 ${percent}% 100%)` }}
      >
        <span aria-hidden="true" className="absolute inset-[14px] flex flex-col items-center justify-center rounded-full bg-(--paper)">
          <span className="text-xl leading-tight font-semibold text-(--ink)">{percent === null ? "—" : `${percent}%`}</span>
          <span className="text-xs text-(--muted)">{percent === null ? "no reading" : "in use"}</span>
        </span>
      </div>
      <p className="m-0 text-xs text-(--muted)">
        {window} low {formatEndpointMetric(low)} · high {formatEndpointMetric(high)}
      </p>
    </figure>
  );
}

function StatusBanner({ status }: { status: DeviceStatus }) {
  const advice = ADVICE[status.tone];
  if (!advice) return null;
  const { surface, text, icon: Icon } = toneStyles[status.tone];
  return (
    <div role={status.tone === "crit" ? "alert" : "status"} className={cx("flex items-start gap-3 rounded-[10px] px-5 py-4", surface)}>
      <Icon size={18} aria-hidden="true" className={cx("mt-0.5 shrink-0", text)} />
      <p className="m-0 grid gap-0.5">
        <span className={cx("font-semibold", text)}>
          {status.label}: {status.reason}
        </span>
        <span className="text-(--slate)">{advice}</span>
      </p>
    </div>
  );
}

function FreshnessNotice({ endpoint }: { endpoint: EndpointDetailData }) {
  if (endpoint.telemetry_freshness === "current") return null;
  const stale = endpoint.telemetry_freshness === "stale";
  return (
    <div role="status" className="flex items-start gap-3 rounded-[10px] bg-(--amber-soft) px-5 py-4">
      <p className="m-0 grid gap-0.5">
        <span className="font-semibold text-[#89500b]">{stale ? "These readings are older than expected" : "No readings have been reported yet"}</span>
        <span className="text-(--slate)">
          {stale
            ? `The latest check-in is more than ${Math.round(endpoint.stale_after_seconds / 60)} minutes old, so the numbers below may be out of date.`
            : "The device is enrolled, but it has not sent processor, memory or disk readings yet."}
        </span>
      </p>
    </div>
  );
}

function ExactValues({ endpoint }: { endpoint: EndpointDetailData }) {
  if (endpoint.telemetry.length === 0) return <p className="m-0 px-5 pb-4 text-sm text-(--muted)">No check-ins in this window. Choose a longer window or wait for the next check-in.</p>;
  return (
    <details className="border-t border-(--line) px-5 py-3">
      <summary className={cx("cursor-pointer rounded text-sm font-semibold text-(--primary-strong)", focusRing)}>Show exact values ({endpoint.telemetry.length} check-ins)</summary>
      <div className="mt-3 max-h-80 overflow-auto">
        <table className="w-full min-w-[640px] border-collapse text-left text-[13px]">
          <caption className="sr-only">Readings for each check-in</caption>
          <thead className="bg-(--fog) text-xs text-(--muted)">
            <tr>
              {["Time", "Processor", "Memory", "Disk", "Uptime", "Signed in"].map((heading) => (
                <th key={heading} scope="col" className="px-3 py-2 font-semibold">
                  {heading}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {endpoint.telemetry.map((sample) => (
              <tr key={sample.ts} className="border-t border-(--line)">
                <td className="px-3 py-1.5 whitespace-nowrap">{formatEndpointDateTime(sample.ts)}</td>
                <td className="px-3 py-1.5">{formatEndpointMetric(sample.cpu_percent)}</td>
                <td className="px-3 py-1.5">{formatEndpointMetric(sample.mem_percent)}</td>
                <td className="px-3 py-1.5">{formatEndpointMetric(sample.disk_percent)}</td>
                <td className="px-3 py-1.5">{formatEndpointUptime(sample.uptime_seconds)}</td>
                <td className="px-3 py-1.5 font-(family-name:--font-data)">{sample.logged_in_user ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {endpoint.history_truncated ? <p className="m-0 mt-2 text-xs text-(--muted)">Only the latest {endpoint.history_limit} check-ins are shown. Choose a shorter window to see them all.</p> : null}
    </details>
  );
}

function kindLabel(kind: string) {
  return commandKindDefinitions.find((definition) => definition.kind === kind)?.label ?? kind;
}

function RecentCommands({ endpoint, commands, now }: { endpoint: EndpointDetailData; commands: CommandHistoryItem[] | null; now: Date }) {
  const base = `/endpoints/${encodeURIComponent(endpoint.id)}/commands`;
  return (
    <Card title="Recent actions on this device" action={<Link href={base} className={cx("rounded text-sm font-semibold text-(--primary-strong) no-underline hover:underline", focusRing)}>All commands</Link>}>
      {commands === null ? (
        <p role="alert" className="m-0 px-5 py-4 text-sm text-(--muted)">
          Command history could not be loaded. Nothing was changed.
        </p>
      ) : commands.length === 0 ? (
        <p className="m-0 px-5 py-4 text-sm text-(--muted)">No commands have been sent to this device.</p>
      ) : (
        <ul className="m-0 list-none p-0">
          {commands.map((command) => {
            const badge = commandBadge(command.status);
            return (
              <li key={command.id} className="border-t border-(--line) first:border-t-0">
                <Link
                  href={`${base}/${encodeURIComponent(command.id)}`}
                  className={cx("flex items-center gap-3 px-5 py-3 text-(--slate) no-underline hover:bg-(--primary-tint)", focusRing, "focus-visible:-outline-offset-2")}
                >
                  <span className="grid min-w-0 flex-1 gap-0.5">
                    <span className="font-semibold text-(--ink)">{kindLabel(command.kind)}</span>
                    <span className="text-xs text-(--muted)">
                      Sent {formatSeen(command.created_at, now)} · <span className="font-(family-name:--font-data)">{command.id.slice(0, 8)}</span>
                    </span>
                  </span>
                  <StatusBadge tone={badge.tone}>{badge.label}</StatusBadge>
                  <ChevronRight size={16} aria-hidden="true" className="shrink-0 text-(--muted)" />
                </Link>
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}

function SummaryTab({ endpoint, commands, now }: { endpoint: EndpointDetailData; commands: CommandHistoryItem[] | null; now: Date }) {
  const sample = endpoint.current_telemetry;
  const window = formatHistoryWindow(endpoint.history_hours);
  const trust = TRUST_LABELS[endpoint.trust_state];
  return (
    <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,420px),1fr))] items-start gap-6">
      <Card
        title="Current readings"
        sub={sample ? `Last check-in ${formatEndpointDateTime(sample.ts)}` : "Waiting for the first check-in"}
        action={
          <nav aria-label="History window" className="flex gap-1">
            {RANGES.map((hours) => (
              <Link
                key={hours}
                href={`/endpoints/${encodeURIComponent(endpoint.id)}?hours=${hours}`}
                aria-current={endpoint.history_hours === hours ? "true" : undefined}
                className={cx(
                  "rounded-full border px-2.5 py-1 text-xs font-semibold no-underline",
                  endpoint.history_hours === hours ? "border-(--primary-on-dark) bg-(--primary-soft) text-(--primary-press)" : "border-(--line-strong) text-(--slate) hover:bg-(--primary-tint)",
                  focusRing,
                )}
              >
                {formatHistoryWindow(hours)}
              </Link>
            ))}
          </nav>
        }
      >
        <div className="grid grid-cols-[repeat(auto-fit,minmax(140px,1fr))] gap-6 px-5 py-6">
          {READINGS.map((reading) => {
            const range = readingRange(sample, endpoint.telemetry, reading.key);
            return <Pie key={reading.key} label={reading.label} icon={reading.icon} value={range.latest} low={range.low} high={range.high} window={window} />;
          })}
        </div>
        <ExactValues endpoint={endpoint} />
      </Card>
      <div className="grid gap-6">
        <Card title="About this device">
          <div className="px-5 py-4">
            <DefinitionList
              items={[
                { term: "Site", value: `${endpoint.site_name} · ${endpoint.client_name}` },
                { term: "System", value: [endpoint.os, endpoint.os_version].filter(Boolean).join(" ") || "Unknown" },
                { term: "Last seen", value: endpoint.last_seen_at ? `${formatSeen(endpoint.last_seen_at, now)} (${formatEndpointDateTime(endpoint.last_seen_at)})` : "Never" },
                { term: "Signed in", value: sample?.logged_in_user ? <span className="font-(family-name:--font-data)">{sample.logged_in_user}</span> : "Nobody reported" },
                { term: "Uptime", value: formatEndpointUptime(sample?.uptime_seconds ?? null) },
                { term: "Agent version", value: formatAgentVersion(endpoint.agent_version, "Unknown") },
                {
                  term: "Agent trust",
                  value: (
                    <span className="grid justify-items-start gap-1">
                      <StatusBadge tone={trust.tone}>{trust.label}</StatusBadge>
                      <span className="text-xs text-(--muted)">{trust.detail}</span>
                    </span>
                  ),
                },
                { term: "Device ID", value: <span className="font-(family-name:--font-data) text-[13px] break-all">{endpoint.id}</span> },
                { term: "Enrolled", value: formatEndpointDateTime(endpoint.enrolled_at) },
              ]}
            />
          </div>
        </Card>
        <RecentCommands endpoint={endpoint} commands={commands} now={now} />
      </div>
    </div>
  );
}

function RemoteTab({ endpoint, operator }: { endpoint: EndpointDetailData; operator: DashboardOperator }) {
  const trusted = endpoint.trust_state === "active";
  // The shell and desktop panels carry their own headings and consent copy.
  return (
    <div className="grid gap-6">
      <ShellSessionPanel
        endpointId={endpoint.id}
        trusted={trusted}
        capable={endpoint.supported_capabilities.includes(SHELL_SESSION_CAPABILITY)}
        canExecuteScripts={endpoint.script_execution_allowed}
      />
      <RemoteDesktopPanel endpointId={endpoint.id} />
      <Card title="Support chat" sub="Start a NodeLink Support conversation with the person signed in to this device.">
        <div className="p-5">
          <SupportChatLaunchButton
            endpointId={endpoint.id}
            capable={endpoint.supported_capabilities.includes("support-chat-launch-v1")}
            trusted={trusted}
            canOpen={operator.role !== "readonly"}
          />
        </div>
      </Card>
    </div>
  );
}

export function EndpointDetailView({ endpoint, operator, status, commands, tab, now: nowIso }: EndpointDetailViewProps) {
  const now = new Date(nowIso);
  const base = `/endpoints/${encodeURIComponent(endpoint.id)}`;
  const canCommand = operator.role !== "readonly" && endpoint.trust_state === "active";
  return (
    <PageStack>
      <PageHeader
        breadcrumb={[{ label: "Devices" }, { label: "Endpoints", href: "/endpoints" }, { label: endpoint.hostname }]}
        title={<span className="font-(family-name:--font-data)">{endpoint.hostname}</span>}
        status={<StatusBadge tone={status.tone}>{status.label}</StatusBadge>}
        description={[[endpoint.os, endpoint.os_version].filter(Boolean).join(" "), endpoint.site_name, endpoint.client_name].filter(Boolean).join(" · ")}
        actions={
          <>
            <ButtonLink href={`/assistant?client_id=${encodeURIComponent(endpoint.client_id)}&endpoint_id=${encodeURIComponent(endpoint.id)}`} icon={Bot}>
              Ask the assistant
            </ButtonLink>
            {canCommand ? (
              <ButtonLink href={`${base}/commands`} variant="primary" icon={TerminalSquare}>
                Restart or run a command
              </ButtonLink>
            ) : null}
          </>
        }
      />
      <StatusBanner status={status} />
      <FreshnessNotice endpoint={endpoint} />
      <TabNav
        label="Device sections"
        tabs={[
          { label: "Summary", href: base, current: tab === "summary" },
          { label: "Inventory", href: `${base}/inventory`, current: false },
          { label: "Commands", href: `${base}/commands`, current: false },
          { label: "Remote access", href: `${base}?tab=remote`, current: tab === "remote" },
        ]}
      />
      {tab === "remote" ? <RemoteTab endpoint={endpoint} operator={operator} /> : <SummaryTab endpoint={endpoint} commands={commands} now={now} />}
    </PageStack>
  );
}
