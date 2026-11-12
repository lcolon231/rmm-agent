// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { ChevronLeft, ChevronRight, CircleAlert, CircleCheck, ListChecks, Loader } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { sortTaskRunsByAttention } from "@/lib/automation-presentation-core";
import { commandKindDefinitions, describeCommandStatus } from "@/lib/command-console-core";
import { commandBadge } from "@/lib/endpoint-summary-core";
import {
  formatTaskRunTimestamp,
  taskRunPageHref,
  type CommandStatus,
  type TaskRunFilters,
  type TaskRunHistoryData,
  type TaskRunItem,
} from "@/lib/task-runs-core";

import { PageHeader, PageStack } from "../shell/page-header";
import { Button, ButtonLink } from "../ui/button";
import { cx, focusRing } from "../ui/cx";
import { DataTable, PrimaryCell, TableFooter, type Column } from "../ui/data-table";
import { DefinitionList, Drawer } from "../ui/drawer";
import { FilterBar } from "../ui/filter-bar";
import { StatRow, StatTile } from "../ui/stat-tile";
import { EmptyState, ErrorState } from "../ui/states";
import { StatusBadge, toneStyles } from "../ui/status-badge";

const STATUS_OPTIONS: CommandStatus[] = ["queued", "dispatched", "running", "result_pending", "succeeded", "failed", "expired"];

const KIND_OPTIONS: Array<[string, string]> = [
  ["powershell", "PowerShell"],
  ["shell", "Shell"],
  ["collect_inventory", "Collect inventory"],
  ["reboot", "Restart endpoint"],
  ["shutdown", "Shut down endpoint"],
  ["cancel_power_action", "Cancel power action"],
];

const control = cx("h-10 rounded-lg border border-(--line-strong) bg-(--paper) px-3 text-sm text-(--ink)", focusRing);

export function kindLabel(kind: string) {
  return commandKindDefinitions.find((definition) => definition.kind === kind)?.label ?? kind;
}

function runHref(run: TaskRunItem) {
  return `/endpoints/${encodeURIComponent(run.agent_id)}/commands/${encodeURIComponent(run.id)}`;
}

function origin(run: TaskRunItem) {
  if (run.script_version_id) return <span className="font-(family-name:--font-data) text-[13px]">Script {run.script_version_id.slice(0, 8)}</span>;
  return "Not from the library";
}

function FilterForm({ filters, filtered }: { filters: TaskRunFilters; filtered: boolean }) {
  // A plain GET form: works before hydration and keeps the URL as the source of truth.
  return (
    <form role="search" aria-label="Filter tasks" method="get" action="/tasks" className="flex flex-wrap items-center gap-3">
      <select aria-label="Filter by status" defaultValue={filters.status ?? ""} name="status" className={control}>
        <option value="">All statuses</option>
        {STATUS_OPTIONS.map((status) => <option key={status} value={status}>{describeCommandStatus(status).label}</option>)}
      </select>
      <select aria-label="Filter by kind" defaultValue={filters.kind ?? ""} name="kind" className={control}>
        <option value="">All kinds</option>
        {KIND_OPTIONS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
      </select>
      <input aria-label="Filter by device ID" defaultValue={filters.agentId ?? ""} name="agent_id" placeholder="Device ID" type="search" className={cx(control, "w-[220px]")} />
      <input aria-label="Sent from date (UTC)" defaultValue={filters.from ?? ""} name="from" type="date" className={control} />
      <input aria-label="Sent to date (UTC)" defaultValue={filters.to ?? ""} name="to" type="date" className={control} />
      <Button type="submit">Apply</Button>
      {filtered ? <ButtonLink href="/tasks" variant="quiet">Clear filters</ButtonLink> : null}
    </form>
  );
}

function Pagination({ filters, page, pageCount }: { filters: TaskRunFilters; page: number; pageCount: number }) {
  const link = cx("flex h-9 items-center gap-1 rounded-lg border border-(--line-strong) bg-(--paper) px-3 text-(--slate) no-underline hover:bg-(--primary-tint)", focusRing);
  return (
    <>
      {page > 1 ? <Link href={taskRunPageHref(filters, page - 1)} rel="prev" className={link}><ChevronLeft size={14} aria-hidden="true" /> Newer</Link> : null}
      <span className="px-2">Page {page} of {pageCount}</span>
      {page < pageCount ? <Link href={taskRunPageHref(filters, page + 1)} rel="next" className={link}>Older <ChevronRight size={14} aria-hidden="true" /></Link> : null}
    </>
  );
}

function RunDrawer({ run, onClose }: { run: TaskRunItem | null; onClose: () => void }) {
  if (!run) return null;
  const badge = commandBadge(run.status);
  const tone = toneStyles[badge.tone];
  const BannerIcon = tone.icon;
  return (
    <Drawer
      open
      onClose={onClose}
      context={<span className="font-(family-name:--font-data)">{run.hostname ?? "Unknown device"}</span>}
      title={kindLabel(run.kind)}
      sub={<span className="font-(family-name:--font-data)">{run.id}</span>}
      record={`Requested by ${run.actor_email ?? "an unrecorded operator"} · ${formatTaskRunTimestamp(run.created_at)}`}
      footer={
        <>
          <ButtonLink href={runHref(run)} variant="primary">Open run and output</ButtonLink>
          <ButtonLink href={`/endpoints/${encodeURIComponent(run.agent_id)}`}>Open device</ButtonLink>
        </>
      }
    >
      <div role="status" className={cx("flex items-start gap-3 rounded-lg px-4 py-3", tone.surface)}>
        <BannerIcon size={18} aria-hidden="true" className={cx("mt-0.5 shrink-0", tone.text)} />
        <p className="m-0 grid gap-0.5">
          <span className={cx("font-semibold", tone.text)}>{badge.label}</span>
          <span className="text-(--slate)">{run.exit_code === null ? "No exit code reported." : `Exit code ${run.exit_code}.`}</span>
        </p>
      </div>
      <DefinitionList
        items={[
          { term: "Device", value: <span className="font-(family-name:--font-data)">{run.hostname ?? "Unknown device"}</span> },
          { term: "Started by", value: run.actor_email ?? "Not recorded" },
          { term: "Origin", value: origin(run) },
          { term: "Sent", value: formatTaskRunTimestamp(run.dispatched_at) },
          { term: "Finished", value: formatTaskRunTimestamp(run.completed_at) },
          { term: "Attempt", value: String(run.attempt) },
        ]}
      />
      <p className="m-0 text-xs text-(--muted)">Output is shown on the run&apos;s own page. Opening it is recorded in the audit log.</p>
    </Drawer>
  );
}

type TaskRunsViewProps = {
  history: TaskRunHistoryData | null;
  filters: TaskRunFilters;
  filtered: boolean;
  pageSize: number;
  pageCount: number;
};

export function TaskRunsView({ history, filters, filtered, pageSize, pageCount }: TaskRunsViewProps) {
  const router = useRouter();
  const [selected, setSelected] = useState<TaskRunItem | null>(null);
  const items = history?.items ?? [];
  const rows = sortTaskRunsByAttention(items);
  const count = (statuses: CommandStatus[]) => items.filter((run) => statuses.includes(run.status)).length;
  const onPage = history ? `Of the ${items.length} on this page` : undefined;

  const columns: Column<TaskRunItem>[] = [
    { key: "task", header: "Task", cell: (run) => <PrimaryCell title={kindLabel(run.kind)} sub={<span className="font-(family-name:--font-data)">{run.id.slice(0, 8)}</span>} /> },
    { key: "status", header: "Status", cell: (run) => { const badge = commandBadge(run.status); return <StatusBadge tone={badge.tone}>{badge.label}</StatusBadge>; } },
    { key: "device", header: "Device", cell: (run) => <PrimaryCell mono title={run.hostname ?? "Unknown device"} sub={run.agent_id} /> },
    { key: "actor", header: "Started by", cell: (run) => run.actor_email ?? <span className="text-(--muted)">Not recorded</span> },
    { key: "origin", header: "Origin", cell: origin },
    { key: "sent", header: "Sent (UTC)", cell: (run) => formatTaskRunTimestamp(run.dispatched_at) },
  ];

  const state = history === null ? (
    <ErrorState title="Task history could not be loaded" body="No runs are shown because the response could not be verified. This does not mean no runs exist" onRetry={() => router.refresh()} />
  ) : rows.length === 0 ? (
    filtered
      ? <EmptyState title="No runs match these filters" body="Clear or widen the filters to see more runs." actionLabel="Clear filters" onAction={() => router.push("/tasks")} />
      : <EmptyState icon={ListChecks} title="No tasks yet" body="No commands have been sent to any device yet." />
  ) : undefined;

  return (
    <PageStack>
      <PageHeader
        breadcrumb={[{ label: "Automation" }, { label: "Tasks" }]}
        title="Tasks"
        description="Every command sent to any device, with who sent it and whether it came from the script library. Open a run to see its output."
      />
      <StatRow>
        <StatTile icon={ListChecks} tone="info" label={filtered ? "Matching runs" : "All runs"} value={history?.total ?? "—"} sub={filtered ? "With these filters" : "Every command sent"} />
        <StatTile icon={CircleAlert} tone={history && count(["failed"]) ? "crit" : "info"} label="Failed" value={history ? count(["failed"]) : "—"} sub={onPage} />
        <StatTile icon={Loader} tone="info" label="Waiting or running" value={history ? count(["queued", "dispatched", "running", "result_pending"]) : "—"} sub={onPage} />
        <StatTile icon={CircleCheck} tone="ok" label="Completed" value={history ? count(["succeeded"]) : "—"} sub={onPage} />
      </StatRow>
      <DataTable
        caption="Task runs"
        columns={columns}
        rows={rows}
        rowKey={(run) => run.id}
        rowLabel={(run) => `Preview ${kindLabel(run.kind)} on ${run.hostname ?? run.agent_id}`}
        onRowSelect={setSelected}
        state={state}
        minWidth={1000}
        filters={<FilterBar><FilterForm filters={filters} filtered={filtered} /></FilterBar>}
        footer={history && rows.length > 0
          ? <TableFooter shown={rows.length} total={history.total} sortNote={`failed, expired, waiting, running, completed on this page · ${pageSize} per page`} pagination={<Pagination filters={filters} page={history.page} pageCount={pageCount} />} />
          : null}
      />
      <RunDrawer run={selected} onClose={() => setSelected(null)} />
    </PageStack>
  );
}

