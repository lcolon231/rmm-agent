// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { BellRing, CircleAlert, CircleCheck, TriangleAlert, UserX } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { formatMonitoringTimestamp, type MonitoringAlert } from "@/lib/monitoring-core";
import {
  ALERT_FILTER_LABELS,
  ALERT_FILTERS,
  alertRiskTone,
  alertSeverityWord,
  alertStateWord,
  alertsHref,
  alertTitle,
  type AlertFilter,
} from "@/lib/monitoring-view-core";

import { PageHeader, PageStack } from "../shell/page-header";
import { ButtonLink } from "../ui/button";
import { cx } from "../ui/cx";
import { DataTable, PrimaryCell, TableFooter, type Column } from "../ui/data-table";
import { DefinitionList, Drawer } from "../ui/drawer";
import { FilterBar, FilterChip } from "../ui/filter-bar";
import { StatRow, StatTile } from "../ui/stat-tile";
import { EmptyState, ErrorState } from "../ui/states";
import { StatusBadge, toneStyles } from "../ui/status-badge";

export type AlertCounts = Record<AlertFilter, number>;

/** The server returns at most this many alerts, most recently observed first. */
export const ALERT_LIST_LIMIT = 200;

type AlertsViewProps = {
  filter: AlertFilter;
  /** null when the alert list could not be loaded. */
  rows: MonitoringAlert[] | null;
  loaded: number;
  counts: AlertCounts | null;
  unassigned: number | null;
};

function when(value: string | null) {
  return value ? formatMonitoringTimestamp(value) : "Not recorded";
}

function latestResult(alert: MonitoringAlert) {
  const severity = alertSeverityWord(alert.last_result_status).label;
  return alert.last_value === null ? severity : `${severity} · reading ${alert.last_value}`;
}

function AlertDrawer({ alert, onClose }: { alert: MonitoringAlert | null; onClose: () => void }) {
  if (!alert) return null;
  const tone = toneStyles[alertRiskTone(alert)];
  const BannerIcon = tone.icon;
  const state = alertStateWord(alert.state);
  const href = `/alerts/${encodeURIComponent(alert.id)}`;
  return (
    <Drawer
      open
      onClose={onClose}
      context={<>Device <span className="font-(family-name:--font-data)">{alert.agent_id}</span></>}
      title={alertTitle(alert.check_key)}
      sub={`Policy ${alert.policy_id}`}
      record={
        alert.acknowledged_at
          ? `Acknowledged by ${alert.acknowledged_by ?? "an unrecorded operator"} on ${formatMonitoringTimestamp(alert.acknowledged_at)}`
          : alert.state === "resolved"
            ? `Resolved ${when(alert.resolved_at)}`
            : "Nobody has acknowledged this alert yet"
      }
      footer={
        <>
          <ButtonLink href={href} variant="primary">
            Open alert
          </ButtonLink>
          <ButtonLink href={`/endpoints/${encodeURIComponent(alert.agent_id)}`}>Open device</ButtonLink>
        </>
      }
    >
      <div role="status" className={cx("flex items-start gap-3 rounded-lg px-4 py-3", tone.surface)}>
        <BannerIcon size={18} aria-hidden="true" className={cx("mt-0.5 shrink-0", tone.text)} />
        <p className="m-0 grid gap-0.5">
          <span className={cx("font-semibold", tone.text)}>{state.label}</span>
          <span className="text-(--slate)">Latest result: {latestResult(alert)}.</span>
        </p>
      </div>
      <DefinitionList
        items={[
          { term: "Opened", value: when(alert.opened_at ?? alert.first_opened_at) },
          { term: "Last seen", value: when(alert.last_observed_at) },
          { term: "Times seen", value: `${alert.occurrence_count} this time · ${alert.total_occurrence_count} in total` },
          { term: "Assigned to", value: alert.assigned_to_email ?? "Nobody" },
          ...(alert.state === "resolved" ? [{ term: "Resolved", value: when(alert.resolved_at) }] : []),
        ]}
      />
      <p className="m-0 text-[13px] text-(--muted)">The full timeline, and who was emailed or sent a webhook, is on the alert page.</p>
    </Drawer>
  );
}

export function AlertsView({ filter, rows, loaded, counts, unassigned }: AlertsViewProps) {
  const router = useRouter();
  const [selected, setSelected] = useState<MonitoringAlert | null>(null);

  const columns: Column<MonitoringAlert>[] = [
    { key: "alert", header: "Alert", cell: (alert) => <PrimaryCell title={alertTitle(alert.check_key)} sub={latestResult(alert)} /> },
    {
      key: "severity",
      header: "Severity",
      cell: (alert) => {
        const word = alertSeverityWord(alert.last_result_status);
        return <StatusBadge tone={word.tone}>{word.label}</StatusBadge>;
      },
    },
    { key: "device", header: "Device", cell: (alert) => <span className="font-(family-name:--font-data) text-[13px]">{alert.agent_id}</span> },
    { key: "opened", header: "Opened", cell: (alert) => when(alert.opened_at ?? alert.first_opened_at) },
    { key: "assigned", header: "Assigned to", cell: (alert) => alert.assigned_to_email ?? <span className="text-(--muted)">Nobody</span> },
    {
      key: "state",
      header: "State",
      cell: (alert) => {
        const word = alertStateWord(alert.state);
        return <StatusBadge tone={word.tone}>{word.label}</StatusBadge>;
      },
    },
  ];

  const state =
    rows === null ? (
      <ErrorState title="Alerts could not be loaded" body="No alert data is shown because the server response could not be verified" onRetry={() => router.refresh()} />
    ) : rows.length === 0 ? (
      filter === "active" ? (
        <EmptyState icon={CircleCheck} title="No alerts need attention" body="Every monitored check is healthy, or its alert has been resolved." />
      ) : (
        <EmptyState title="No alerts match" body="Nothing in the loaded alerts matches this filter." actionLabel="Clear filters" onAction={() => router.push(alertsHref("active"))} />
      )
    ) : undefined;

  const value = (count: number | null | undefined) => (count === null || count === undefined ? "—" : count);
  const capped = loaded >= ALERT_LIST_LIMIT;

  return (
    <PageStack>
      <PageHeader
        breadcrumb={[{ label: "Devices" }, { label: "Alerts" }]}
        title="Alerts"
        description="Problems our monitoring has found. The most serious are listed first."
      />
      <StatRow>
        <StatTile icon={CircleAlert} label="Critical" tone={counts === null ? "off" : counts.critical ? "crit" : "ok"} value={value(counts?.critical)} sub="Not yet resolved" />
        <StatTile icon={TriangleAlert} label="Warning" tone={counts === null ? "off" : counts.warning ? "warn" : "ok"} value={value(counts?.warning)} sub="Not yet resolved" />
        <StatTile icon={BellRing} label="Acknowledged" tone="info" value={value(counts?.acknowledged)} sub="Someone is looking" />
        <StatTile icon={UserX} label="Unassigned" tone={unassigned === null ? "off" : unassigned ? "warn" : "ok"} value={value(unassigned)} sub="Not resolved, nobody assigned" />
      </StatRow>
      <DataTable
        caption="Alerts"
        columns={columns}
        rows={rows ?? []}
        rowKey={(alert) => alert.id}
        rowLabel={(alert) => `Preview ${alertTitle(alert.check_key)} on ${alert.agent_id}`}
        onRowSelect={setSelected}
        state={state}
        minWidth={960}
        filters={
          <FilterBar>
            <div role="group" aria-label="Filter alerts" className="flex flex-wrap gap-2">
              {ALERT_FILTERS.map((name) => (
                <FilterChip key={name} href={alertsHref(name)} selected={filter === name} count={counts?.[name]}>
                  {ALERT_FILTER_LABELS[name]}
                </FilterChip>
              ))}
            </div>
          </FilterBar>
        }
        footer={
          rows && rows.length > 0 ? (
            <TableFooter
              shown={rows.length}
              total={rows.length}
              sortNote={capped ? `most urgent first, from the ${ALERT_LIST_LIMIT} most recently seen alerts` : "most urgent first"}
            />
          ) : null
        }
      />
      <AlertDrawer alert={selected} onClose={() => setSelected(null)} />
    </PageStack>
  );
}
