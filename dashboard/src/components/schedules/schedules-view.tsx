// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { CalendarClock, CircleAlert, Clock, Pause } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { scheduleLastResult } from "@/lib/automation-presentation-core";
import type { OperatorRole } from "@/lib/script-library-core";
import { formatScheduleDateTime, type ScheduledTaskItem, type ScheduledTaskListData } from "@/lib/scheduled-tasks-core";

import { PageHeader, PageStack } from "../shell/page-header";
import { DefinitionList, Drawer } from "../ui/drawer";
import { DataTable, PrimaryCell, TableFooter, type Column } from "../ui/data-table";
import { FilterBar, FilterChip } from "../ui/filter-bar";
import { StatRow, StatTile } from "../ui/stat-tile";
import { EmptyState, ErrorState } from "../ui/states";
import { StatusBadge } from "../ui/status-badge";
import { NewScheduleButton, ScheduleActions } from "./schedule-actions";

type Filter = "all" | "attention" | "active" | "paused";

const KIND: Record<string, string> = { powershell: "PowerShell", shell: "Shell" };

function kindLabel(kind: string) {
  return KIND[kind] ?? kind;
}

function appliesTo(task: ScheduledTaskItem) {
  return task.target_type === "site" ? "Every device at a site" : "One device";
}

function needsAttention(task: ScheduledTaskItem) {
  return scheduleLastResult(task.last_status).attention;
}

/** Last run not sent first, then active, then paused; server order kept within each. */
function sortSchedules(items: readonly ScheduledTaskItem[]) {
  const rank = (task: ScheduledTaskItem) => (needsAttention(task) ? 0 : task.enabled ? 1 : 2);
  return items.map((task, index) => ({ task, index })).sort((a, b) => rank(a.task) - rank(b.task) || a.index - b.index).map(({ task }) => task);
}

function StateBadge({ task }: { task: ScheduledTaskItem }) {
  return task.enabled ? <StatusBadge tone="ok">Active</StatusBadge> : <StatusBadge tone="off">Paused</StatusBadge>;
}

function ScheduleDrawer({ task, canChange, onClose }: { task: ScheduledTaskItem | null; canChange: boolean; onClose: () => void }) {
  if (!task) return null;
  const last = scheduleLastResult(task.last_status);
  return (
    <Drawer
      open
      onClose={onClose}
      context="Schedules"
      title={task.name}
      sub={task.description ?? undefined}
      record={`Created by ${task.created_by_email ?? "an unrecorded operator"} · ${formatScheduleDateTime(task.created_at)}`}
      footer={canChange ? <ScheduleActions task={task} onDeleted={onClose} /> : <span className="text-[13px] text-(--muted)">View only</span>}
    >
      <div><StateBadge task={task} /></div>
      <DefinitionList
        items={[
          { term: "When it runs", value: <span><span className="font-(family-name:--font-data) text-[13px]">{task.cron_expression}</span> · {task.timezone}</span> },
          { term: "Next run", value: task.enabled ? formatScheduleDateTime(task.next_run_at) : "Not while paused" },
          { term: "Last run", value: formatScheduleDateTime(task.last_run_at, "Never") },
          { term: "Last result", value: last.text },
          { term: "Applies to", value: appliesTo(task) },
          { term: task.target_type === "site" ? "Site ID" : "Device ID", value: <span className="font-(family-name:--font-data) text-[13px] break-all">{task.target_id}</span> },
          { term: "Kind", value: kindLabel(task.kind) },
          { term: "Library script", value: task.script_version_id ? <span className="font-(family-name:--font-data) text-[13px] break-all">{task.script_version_id}</span> : "None" },
        ]}
      />
      <p className="m-0 text-xs text-(--muted)">&ldquo;Sent to devices&rdquo; means the commands were sent, not that they finished. Each run&apos;s result is in Tasks.</p>
    </Drawer>
  );
}

export function SchedulesView({ schedules, role }: { schedules: ScheduledTaskListData | null; role: OperatorRole }) {
  const router = useRouter();
  const [filter, setFilter] = useState<Filter>("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const canChange = role !== "readonly";
  const items = schedules?.items ?? [];
  const partial = schedules !== null && schedules.total > items.length;
  const scope = partial ? `Of the first ${items.length} loaded` : undefined;
  const active = items.filter((task) => task.enabled);
  const attention = items.filter(needsAttention);
  const next = [...active].sort((a, b) => Date.parse(a.next_run_at) - Date.parse(b.next_run_at))[0];
  const rows = sortSchedules(items.filter((task) =>
    filter === "all" || (filter === "attention" ? needsAttention(task) : filter === "active" ? task.enabled : !task.enabled)));
  // Look the record up from fresh data so the drawer reflects a refresh.
  const selected = items.find((task) => task.id === selectedId) ?? null;

  const columns: Column<ScheduledTaskItem>[] = [
    { key: "name", header: "Schedule", cell: (task) => <PrimaryCell title={task.name} sub={task.description ?? undefined} /> },
    { key: "when", header: "When it runs", cell: (task) => <PrimaryCell title={<span className="font-(family-name:--font-data) text-[13px] font-normal">{task.cron_expression}</span>} sub={task.timezone} /> },
    { key: "kind", header: "Kind", cell: (task) => kindLabel(task.kind) },
    { key: "target", header: "Applies to", cell: (task) => <PrimaryCell title={appliesTo(task)} sub={<span className="font-(family-name:--font-data)">{task.target_id.slice(0, 12)}…</span>} /> },
    { key: "next", header: "Next run", cell: (task) => (task.enabled ? formatScheduleDateTime(task.next_run_at) : <span className="text-(--muted)">Not while paused</span>) },
    {
      key: "last",
      header: "Last run",
      cell: (task) => {
        const last = scheduleLastResult(task.last_status);
        return <PrimaryCell title={<span className={last.attention ? "text-[#89500b]" : "font-normal text-(--slate)"}>{last.text}</span>} sub={formatScheduleDateTime(task.last_run_at, "Never")} />;
      },
    },
    { key: "state", header: "State", cell: (task) => <StateBadge task={task} /> },
  ];

  const state = schedules === null ? (
    <ErrorState title="Schedules could not be loaded" body="The schedule list could not be verified, so none are shown. This does not mean there are none" onRetry={() => router.refresh()} />
  ) : rows.length === 0 ? (
    filter !== "all"
      ? <EmptyState title="No schedules match" body="Choose a different filter." actionLabel="Clear filters" onAction={() => setFilter("all")} />
      : <EmptyState icon={CalendarClock} title="No schedules yet" body={canChange ? "Use New schedule to run a command on a repeating timetable." : "No schedules have been created yet."} />
  ) : undefined;

  const chips: Array<{ label: string; value: Filter; count: number }> = [
    { label: "All", value: "all", count: items.length },
    { label: "Not sent last run", value: "attention", count: attention.length },
    { label: "Active", value: "active", count: active.length },
    { label: "Paused", value: "paused", count: items.length - active.length },
  ];

  return (
    <PageStack>
      <PageHeader
        breadcrumb={[{ label: "Automation" }, { label: "Schedules" }]}
        title="Schedules"
        description="Commands that run automatically on a repeating timetable, on one device or every device at a site."
        actions={canChange ? <NewScheduleButton /> : <span className="text-[13px] text-(--muted)">View only</span>}
      />
      <StatRow>
        <StatTile icon={Clock} tone="ok" label="Active" value={schedules ? active.length : "—"} sub={scope ?? (schedules ? `${items.length - active.length} paused` : undefined)} />
        <StatTile icon={CalendarClock} tone="info" label="Next run" value={next ? formatScheduleDateTime(next.next_run_at) : "—"} sub={next ? next.name : schedules ? "No active schedules" : undefined} />
        <StatTile icon={CircleAlert} tone={attention.length ? "warn" : "info"} label="Not sent last run" value={schedules ? attention.length : "—"} sub={scope ?? "Skipped or refused"} />
        <StatTile icon={Pause} tone="off" label="Paused" value={schedules ? items.length - active.length : "—"} sub={scope ?? "Will not run until resumed"} />
      </StatRow>
      <DataTable
        caption="Schedules"
        columns={columns}
        rows={rows}
        rowKey={(task) => task.id}
        rowLabel={(task) => `Preview ${task.name}`}
        onRowSelect={(task) => setSelectedId(task.id)}
        state={state}
        minWidth={1080}
        filters={schedules ? (
          <FilterBar>
            <div role="group" aria-label="Filter by state" className="flex flex-wrap gap-2">
              {chips.map((chip) => (
                <FilterChip key={chip.value} selected={filter === chip.value} count={chip.count} onClick={() => setFilter(chip.value)}>{chip.label}</FilterChip>
              ))}
            </div>
          </FilterBar>
        ) : null}
        footer={schedules && rows.length > 0
          ? <TableFooter shown={rows.length} total={schedules.total} sortNote={partial ? "not sent last run first, among those loaded" : "not sent last run first"} />
          : null}
      />
      <ScheduleDrawer task={selected} canChange={canChange} onClose={() => setSelectedId(null)} />
    </PageStack>
  );
}
