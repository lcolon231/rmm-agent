// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { Activity, BellRing, CirclePause, HeartPulse, ListChecks } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { formatMonitoringTimestamp, type MonitoringPolicy } from "@/lib/monitoring-core";
import {
  POLICY_FILTERS,
  policiesHref,
  policyStateWord,
  scopeLabel,
  type PolicyAlertCounts,
  type PolicyFilter,
  type ViewTone,
} from "@/lib/monitoring-view-core";

import { PageHeader, PageStack } from "../shell/page-header";
import { ButtonLink } from "../ui/button";
import { DataTable, PrimaryCell, TableFooter, type Column } from "../ui/data-table";
import { DefinitionList, Drawer } from "../ui/drawer";
import { FilterBar, FilterChip } from "../ui/filter-bar";
import { StatRow, StatTile } from "../ui/stat-tile";
import { EmptyState, ErrorState } from "../ui/states";
import { StatusBadge } from "../ui/status-badge";
import { MonitoringTabs } from "./monitoring-tabs";

export type PolicyRow = {
  policy: MonitoringPolicy;
  /** null when alerts could not be loaded. */
  alerts: PolicyAlertCounts | null;
  tone: ViewTone;
};

type Totals = { all: number; active: number; disabled: number; checks: number };

type PoliciesViewProps = {
  filter: PolicyFilter;
  rows: PolicyRow[] | null;
  totals: Totals | null;
  openAlerts: number | null;
};

const FILTER_LABELS: Record<PolicyFilter, string> = { all: "All", active: "Active", disabled: "Disabled" };

function OpenAlerts({ row }: { row: PolicyRow }) {
  if (row.alerts === null) return <span className="text-(--muted)">Unavailable</span>;
  if (row.alerts.open === 0) return <span className="text-(--muted)">None</span>;
  return <StatusBadge tone={row.alerts.critical ? "crit" : "warn"}>{`${row.alerts.open} open`}</StatusBadge>;
}

function appliesTo(policy: MonitoringPolicy) {
  return <PrimaryCell title={scopeLabel(policy.scope, policy.scope_id)} sub={policy.scope_id ? <span className="font-(family-name:--font-data)">{policy.scope_id}</span> : undefined} />;
}

function PolicyDrawer({ row, onClose }: { row: PolicyRow | null; onClose: () => void }) {
  if (!row) return null;
  const { policy } = row;
  const state = policyStateWord(policy.enabled);
  return (
    <Drawer
      open
      onClose={onClose}
      context="Monitoring policy"
      title={policy.name}
      sub={<span className="font-(family-name:--font-data)">{policy.id}</span>}
      record={`Created ${formatMonitoringTimestamp(policy.created_at)} · now at revision ${policy.current_version}`}
      footer={
        <ButtonLink href={`/monitoring/${encodeURIComponent(policy.id)}`} variant="primary">
          Open policy
        </ButtonLink>
      }
    >
      <DefinitionList
        items={[
          { term: "State", value: <StatusBadge tone={state.tone}>{state.label}</StatusBadge> },
          { term: "Applies to", value: appliesTo(policy) },
          { term: "Checks", value: String(policy.check_count) },
          { term: "Open alerts", value: <OpenAlerts row={row} /> },
          { term: "Revision", value: `v${policy.current_version}` },
        ]}
      />
      <p className="m-0 text-[13px] text-(--muted)">The checks, their limits and the change history are on the policy page.</p>
    </Drawer>
  );
}

export function MonitoringPoliciesView({ filter, rows, totals, openAlerts }: PoliciesViewProps) {
  const router = useRouter();
  const [selected, setSelected] = useState<PolicyRow | null>(null);

  const columns: Column<PolicyRow>[] = [
    { key: "policy", header: "Policy", cell: ({ policy }) => <PrimaryCell title={policy.name} sub={`Revision ${policy.current_version}`} /> },
    { key: "checks", header: "Checks", align: "end", cell: ({ policy }) => policy.check_count },
    { key: "applies", header: "Applies to", cell: ({ policy }) => appliesTo(policy) },
    { key: "alerts", header: "Open alerts", cell: (row) => <OpenAlerts row={row} /> },
    { key: "created", header: "Created", cell: ({ policy }) => formatMonitoringTimestamp(policy.created_at) },
    {
      key: "state",
      header: "State",
      cell: ({ policy }) => {
        const word = policyStateWord(policy.enabled);
        return <StatusBadge tone={word.tone}>{word.label}</StatusBadge>;
      },
    },
  ];

  const state =
    rows === null ? (
      <ErrorState title="Monitoring policies could not be loaded" body="No policies are shown because the server response could not be verified" onRetry={() => router.refresh()} />
    ) : rows.length === 0 ? (
      filter === "all" ? (
        <EmptyState icon={Activity} title="No monitoring policies yet" body="Policies are created through the NodeLink API. Once one exists, it appears here." />
      ) : (
        <EmptyState title="No policies match" body="No policy has this state." actionLabel="Clear filters" onAction={() => router.push(policiesHref("all"))} />
      )
    ) : undefined;

  return (
    <PageStack>
      <PageHeader
        breadcrumb={[{ label: "Devices" }, { label: "Monitoring" }]}
        title="Monitoring"
        description="The checks NodeLink runs on devices. Where policies overlap, the most specific one wins for each check."
      />
      <StatRow>
        <StatTile icon={HeartPulse} label="Active policies" tone="info" value={totals?.active ?? "—"} sub={totals ? `${totals.all} in total` : "Unavailable"} />
        <StatTile icon={CirclePause} label="Disabled" tone={totals?.disabled ? "off" : "info"} value={totals?.disabled ?? "—"} sub="Not checking anything" />
        <StatTile icon={ListChecks} label="Checks configured" tone="info" value={totals?.checks ?? "—"} sub="Across all policies" />
        <StatTile
          icon={BellRing}
          label="Alerts open"
          tone={openAlerts === null ? "off" : openAlerts ? "warn" : "ok"}
          value={openAlerts ?? "—"}
          sub={openAlerts === null ? "Alerts could not be loaded" : "Not yet resolved"}
        />
      </StatRow>
      <MonitoringTabs current="policies" />
      <DataTable
        caption="Monitoring policies"
        columns={columns}
        rows={rows ?? []}
        rowKey={({ policy }) => policy.id}
        rowLabel={({ policy }) => `Preview ${policy.name}`}
        onRowSelect={setSelected}
        state={state}
        minWidth={900}
        filters={
          <FilterBar>
            <div role="group" aria-label="Filter by state" className="flex flex-wrap gap-2">
              {POLICY_FILTERS.map((name) => (
                <FilterChip key={name} href={policiesHref(name)} selected={filter === name} count={totals?.[name]}>
                  {FILTER_LABELS[name]}
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
              sortNote={openAlerts === null ? "disabled first; alert counts unavailable" : "critical alerts first, then disabled policies, then other open alerts"}
            />
          ) : null
        }
      />
      <PolicyDrawer row={selected} onClose={() => setSelected(null)} />
    </PageStack>
  );
}
