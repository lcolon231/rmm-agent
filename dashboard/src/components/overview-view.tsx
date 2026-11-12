// SPDX-License-Identifier: AGPL-3.0-only

import { Bell, ChevronRight, ClipboardCheck, Monitor, Shield } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import type { ApprovalRequest } from "@/lib/approvals-core";
import type { DeviceStatus } from "@/lib/device-status-core";
import { formatSeen } from "@/lib/device-status-core";
import type { EndpointListItem } from "@/lib/endpoint-list";
import { formatRequestKind, type ActivityRow, type SeverityRow } from "@/lib/overview-core";

import { PageHeader, PageStack } from "./shell/page-header";
import { ButtonLink } from "./ui/button";
import { cx, focusRing } from "./ui/cx";
import { StatRow, StatTile, cardClass } from "./ui/stat-tile";
import { EmptyState, ErrorState } from "./ui/states";
import { StatusBadge, type StatusTone } from "./ui/status-badge";

export type OverviewData = {
  scopeName: string | null;
  now: string;
  devices: { total: number; online: number; offline: number } | null;
  attention: Array<{ device: EndpointListItem; status: DeviceStatus }> | null;
  alerts: { total: number; rows: SeverityRow[] } | null;
  compliance: { percent: number; compliant: number; inScope: number } | null | "error";
  approvals: ApprovalRequest[] | null;
  activity: ActivityRow[] | null;
};

const ATTENTION_LIMIT = 6;
const APPROVAL_LIMIT = 3;
const COMPLIANCE_TARGET = 95;

function Card({ title, sub, action, children, className }: { title: string; sub?: string; action?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section aria-label={title} className={cx(cardClass, "overflow-hidden", className)}>
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

function CardLink({ href, children }: { href: string; children: string }) {
  return (
    <Link href={href} className={cx("rounded text-sm font-semibold text-(--primary-strong) no-underline hover:underline", focusRing)}>
      {children}
    </Link>
  );
}

function Bar({ percent, tone }: { percent: number; tone: string }) {
  return (
    <span aria-hidden="true" className="block h-2 w-full overflow-hidden rounded-full bg-[#ece9f5]">
      <span className={cx("block h-full rounded-full", tone)} style={{ width: `${Math.min(100, Math.max(0, percent))}%` }} />
    </span>
  );
}

function NeedsAttention({ attention, now }: { attention: OverviewData["attention"]; now: Date }) {
  if (attention === null) return <ErrorState body="Device health could not be loaded" />;
  if (attention.length === 0) {
    return <EmptyState title="Nothing needs you right now" body="No device is offline, has an open critical alert, or has a reading at 90% or above." />;
  }
  const shown = attention.slice(0, ATTENTION_LIMIT);
  return (
    <>
      <ul className="m-0 list-none p-0">
        {shown.map(({ device, status }) => (
          <li key={device.id} className="border-t border-(--line) first:border-t-0">
            <Link
              href={`/endpoints/${encodeURIComponent(device.id)}`}
              className={cx("flex items-center gap-4 px-5 py-3.5 text-(--slate) no-underline hover:bg-(--primary-tint)", focusRing, "focus-visible:-outline-offset-2")}
            >
              <StatusBadge tone={status.tone} className="w-[104px] justify-center">
                {status.label}
              </StatusBadge>
              <span className="grid min-w-0 flex-1 gap-0.5">
                <span className="truncate font-(family-name:--font-data) text-[13px] font-semibold text-(--ink)">{device.hostname}</span>
                <span className="text-sm">{status.reason}</span>
                <span className="text-xs text-(--muted)">
                  {device.site_name} · seen {device.last_seen_at ? formatSeen(device.last_seen_at, now) : "never"}
                </span>
              </span>
              <ChevronRight size={16} aria-hidden="true" className="shrink-0 text-(--muted)" />
            </Link>
          </li>
        ))}
      </ul>
      <p className="m-0 border-t border-(--line) px-5 py-3 text-xs text-(--muted)">
        {attention.length > shown.length
          ? `${attention.length - shown.length} more need attention. The full list is on Endpoints.`
          : "These are the most urgent devices loaded. The full list is on Endpoints."}
      </p>
    </>
  );
}

const severityBar: Record<SeverityRow["tone"], string> = { crit: "bg-(--red)", warn: "bg-(--amber)", off: "bg-(--chrome-muted)" };

function AlertsBySeverity({ alerts, unscoped }: { alerts: OverviewData["alerts"]; unscoped: boolean }) {
  return (
    <Card title="Open alerts by severity" sub={unscoped ? "Across all clients" : undefined} action={<CardLink href="/alerts">Open alerts</CardLink>}>
      {alerts === null ? (
        <ErrorState body="Alerts could not be loaded" />
      ) : (
        <ul className="m-0 grid list-none gap-3 px-5 py-4">
          {alerts.rows.map((row) => (
            <li key={row.label} className="grid grid-cols-[104px_1fr_32px] items-center gap-3">
              <StatusBadge tone={row.tone} className="justify-center">
                {row.label}
              </StatusBadge>
              <Bar percent={alerts.total ? (row.count / alerts.total) * 100 : 0} tone={severityBar[row.tone]} />
              <span className="text-right font-semibold text-(--ink) tabular-nums">{row.count}</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function PatchCompliance({ compliance }: { compliance: OverviewData["compliance"] }) {
  return (
    <Card title="Patch compliance" sub={`Target ${COMPLIANCE_TARGET}%`} action={<CardLink href="/patch-compliance">Open patch compliance</CardLink>}>
      {compliance === "error" ? (
        <ErrorState body="Patch compliance could not be loaded" />
      ) : compliance === null ? (
        <p className="m-0 px-5 py-4 text-sm text-(--muted)">No devices are in scope for patch compliance yet.</p>
      ) : (
        <div className="grid gap-3 px-5 py-4">
          <p className="m-0 flex flex-wrap items-baseline gap-3">
            <span className="text-[32px] leading-none font-semibold text-(--ink)">{compliance.percent}%</span>
            <span className="text-sm">
              {compliance.compliant} of {compliance.inScope} devices fully patched
            </span>
          </p>
          <Bar percent={compliance.percent} tone={compliance.percent >= COMPLIANCE_TARGET ? "bg-(--success)" : "bg-(--amber)"} />
        </div>
      )}
    </Card>
  );
}

function WaitingForApproval({ approvals, now }: { approvals: OverviewData["approvals"]; now: Date }) {
  return (
    <Card title="Waiting for your approval" action={<CardLink href="/approvals">Open approvals</CardLink>}>
      {approvals === null ? (
        <ErrorState body="Approval requests could not be loaded" />
      ) : approvals.length === 0 ? (
        <p className="m-0 px-5 py-4 text-sm text-(--muted)">Nothing is waiting for you.</p>
      ) : (
        <ul className="m-0 list-none p-0">
          {approvals.slice(0, APPROVAL_LIMIT).map((request) => (
            <li key={request.id} className="flex items-center gap-3 border-t border-(--line) px-5 py-3 first:border-t-0">
              <span className="grid min-w-0 flex-1 gap-0.5">
                <span className="font-semibold text-(--ink)">{formatRequestKind(request.kind)}</span>
                <span className="truncate text-xs text-(--muted)">
                  Requested by {request.requested_by_email} · {formatSeen(request.created_at, now)}
                </span>
              </span>
              <ButtonLink href="/approvals" size="compact">
                Review
              </ButtonLink>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function RecentActivity({ activity, now, unscoped }: { activity: OverviewData["activity"]; now: Date; unscoped: boolean }) {
  return (
    <Card
      title="Recent activity"
      sub={`Who did what, and when, from the audit record.${unscoped ? " Across all clients." : ""}`}
      action={<CardLink href="/audit">Open audit log</CardLink>}
    >
      {activity === null ? (
        <ErrorState body="The audit record could not be loaded" />
      ) : activity.length === 0 ? (
        <p className="m-0 px-5 py-4 text-sm text-(--muted)">No activity has been recorded yet.</p>
      ) : (
        <ul className="m-0 list-none p-0">
          {activity.map((row) => (
            <li key={row.id} className="flex flex-wrap items-baseline gap-x-4 gap-y-1 border-t border-(--line) px-5 py-3 first:border-t-0">
              <time dateTime={row.ts} className="w-24 shrink-0 text-xs text-(--muted)">
                {formatSeen(row.ts, now)}
              </time>
              <span className="min-w-0 flex-1">
                <strong className="font-semibold text-(--ink)">{row.actor}</strong> {row.verb}
                {row.target ? <span className="ml-1 font-(family-name:--font-data) text-[13px] text-(--ink)">{row.target}</span> : null}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function tileTone(condition: { crit?: boolean; warn?: boolean }): StatusTone {
  if (condition.crit) return "crit";
  if (condition.warn) return "warn";
  return "ok";
}

export function OverviewView({ data }: { data: OverviewData }) {
  const now = new Date(data.now);
  const scoped = data.scopeName !== null;
  const critical = data.alerts?.rows.find((row) => row.tone === "crit")?.count ?? 0;
  const compliance = data.compliance === "error" ? null : data.compliance;

  return (
    <PageStack>
      <PageHeader
        breadcrumb={[{ label: data.scopeName ?? "All clients" }, { label: "Overview" }]}
        title="Overview"
        description={`How ${data.scopeName ? `${data.scopeName}’s` : "your clients’"} devices are doing right now, and what needs you first.`}
        actions={
          <ButtonLink href="/alerts" variant="primary" icon={Bell}>
            Review open alerts
          </ButtonLink>
        }
      />
      <StatRow>
        <StatTile
          icon={Monitor}
          label="Devices online"
          tone={data.devices ? tileTone({ warn: data.devices.offline > 0 }) : "off"}
          value={data.devices ? data.devices.online : "—"}
          sub={data.devices ? `of ${data.devices.total} · ${data.devices.offline} offline` : "Could not be loaded"}
        />
        <StatTile
          icon={Bell}
          label="Open alerts"
          tone={data.alerts ? tileTone({ crit: critical > 0, warn: data.alerts.total > 0 }) : "off"}
          value={data.alerts ? data.alerts.total : "—"}
          sub={data.alerts ? `${critical} critical${scoped ? " · all clients" : ""}` : "Could not be loaded"}
        />
        <StatTile
          icon={Shield}
          label="Patch compliance"
          tone={compliance ? tileTone({ warn: compliance.percent < COMPLIANCE_TARGET }) : "off"}
          value={compliance ? `${compliance.percent}%` : "—"}
          sub={data.compliance === "error" ? "Could not be loaded" : compliance ? `Target ${COMPLIANCE_TARGET}%` : "No devices in scope"}
        />
        <StatTile
          icon={ClipboardCheck}
          label="Pending approvals"
          tone={data.approvals ? (data.approvals.length > 0 ? "info" : "ok") : "off"}
          value={data.approvals ? data.approvals.length : "—"}
          sub={data.approvals ? "Waiting for you" : "Could not be loaded"}
        />
      </StatRow>
      <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,420px),1fr))] items-start gap-6">
        <Card title="Needs attention" sub="Most at-risk devices first" action={<CardLink href="/endpoints">View all devices</CardLink>}>
          <NeedsAttention attention={data.attention} now={now} />
        </Card>
        <div className="grid gap-6">
          <AlertsBySeverity alerts={data.alerts} unscoped={scoped} />
          <PatchCompliance compliance={data.compliance} />
          <WaitingForApproval approvals={data.approvals} now={now} />
        </div>
      </div>
      <RecentActivity activity={data.activity} now={now} unscoped={scoped} />
    </PageStack>
  );
}
