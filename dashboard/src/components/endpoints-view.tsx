// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { ChevronLeft, ChevronRight, CircleAlert, Clock, Download, Laptop, Monitor, Plus, Server, TerminalSquare, WifiOff } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import type { DeviceStatus } from "@/lib/device-status-core";
import { formatSeen } from "@/lib/device-status-core";
import { formatAgentVersion } from "@/lib/endpoint-detail-core";
import type { EndpointListItem } from "@/lib/endpoint-list";
import { csvCell, endpointsHref, type EndpointsQuery, type EndpointStatusFilter } from "@/lib/endpoints-list-core";

import { PageHeader, PageStack } from "./shell/page-header";
import { Button, ButtonLink } from "./ui/button";
import { cx, focusRing } from "./ui/cx";
import { DataTable, PrimaryCell, TableFooter, type Column } from "./ui/data-table";
import { DefinitionList, Drawer } from "./ui/drawer";
import { FilterBar, FilterChip } from "./ui/filter-bar";
import { Meter } from "./ui/meter";
import { StatRow, StatTile } from "./ui/stat-tile";
import { EmptyState, ErrorState } from "./ui/states";
import { StatusBadge, toneStyles } from "./ui/status-badge";

export type EndpointRow = { item: EndpointListItem; status: DeviceStatus };

type Counts = { all: number | null; online: number | null; offline: number | null; pending: number | null };

type EndpointsViewProps = {
  query: EndpointsQuery;
  rows: EndpointRow[] | null;
  total: number;
  pageSize: number;
  counts: Counts;
  alertsUnavailable: boolean;
  canEnroll: boolean;
  now: string;
};

function osLabel(item: EndpointListItem) {
  return [item.os, item.os_version].filter(Boolean).join(" ") || "Unknown system";
}

function DeviceIcon({ item }: { item: EndpointListItem }) {
  const Icon = /server/i.test(`${item.os} ${item.os_version}`) ? Server : Laptop;
  return <Icon size={18} aria-hidden="true" className="shrink-0 text-(--muted)" />;
}

function seen(item: EndpointListItem, now: Date) {
  return item.last_seen_at ? formatSeen(item.last_seen_at, now) : "Never";
}

function exportCsv(rows: EndpointRow[], now: Date) {
  const lines = [
    ["Device", "Status", "Reason", "Client", "Site", "Last seen", "Signed in", "Processor %", "Memory %", "Disk %"],
    ...rows.map(({ item, status }) => [
      item.hostname,
      status.label,
      status.reason,
      item.client_name,
      item.site_name,
      item.last_seen_at ?? "",
      item.logged_in_user ?? "",
      item.cpu_percent,
      item.mem_percent,
      item.disk_percent,
    ]),
  ];
  const csv = lines.map((line) => line.map(csvCell).join(",")).join("\r\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `nodelink-devices-${now.toISOString().slice(0, 10)}.csv`;
  anchor.click();
  URL.revokeObjectURL(url);
}

function SearchForm({ query }: { query: EndpointsQuery }) {
  // A plain GET form: works before hydration and keeps the other filters.
  return (
    <form role="search" action="/endpoints" method="get" className="relative w-full max-w-[320px] min-w-[200px] flex-1">
      {query.client ? <input type="hidden" name="client" value={query.client} /> : null}
      {query.site ? <input type="hidden" name="site" value={query.site} /> : null}
      {query.status ? <input type="hidden" name="status" value={query.status} /> : null}
      <input
        type="search"
        name="search"
        maxLength={100}
        defaultValue={query.search ?? ""}
        aria-label="Search devices by name"
        placeholder="Search by device name"
        className={cx("h-10 w-full rounded-lg border border-(--line-strong) bg-(--paper) px-3 text-sm text-(--ink)", focusRing)}
      />
    </form>
  );
}

function Pagination({ query, total, pageSize }: { query: EndpointsQuery; total: number; pageSize: number }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const iconLink = "flex size-9 items-center justify-center rounded-lg border border-(--line-strong) bg-(--paper) text-(--slate) hover:bg-(--primary-tint)";
  const disabled = "flex size-9 items-center justify-center rounded-lg border border-(--line) bg-(--fog) text-(--muted)";
  return (
    <>
      {query.page > 1 ? (
        <Link href={endpointsHref(query, { page: query.page - 1 })} aria-label="Previous page" className={cx(iconLink, focusRing)}>
          <ChevronLeft size={16} aria-hidden="true" />
        </Link>
      ) : (
        <span aria-hidden="true" className={disabled}>
          <ChevronLeft size={16} />
        </span>
      )}
      <span className="px-2">
        Page {Math.min(query.page, pages)} of {pages}
      </span>
      {query.page < pages ? (
        <Link href={endpointsHref(query, { page: query.page + 1 })} aria-label="Next page" className={cx(iconLink, focusRing)}>
          <ChevronRight size={16} aria-hidden="true" />
        </Link>
      ) : (
        <span aria-hidden="true" className={disabled}>
          <ChevronRight size={16} />
        </span>
      )}
    </>
  );
}

function DeviceDrawer({ row, onClose, now }: { row: EndpointRow | null; onClose: () => void; now: Date }) {
  if (!row) return null;
  const { item, status } = row;
  const tone = toneStyles[status.tone];
  const BannerIcon = tone.icon;
  const href = `/endpoints/${encodeURIComponent(item.id)}`;
  return (
    <Drawer
      open
      onClose={onClose}
      context={`${item.client_name} · ${item.site_name}`}
      title={<span className="font-(family-name:--font-data)">{item.hostname}</span>}
      sub={osLabel(item)}
      footer={
        <>
          <ButtonLink href={href} variant="primary">
            Open device
          </ButtonLink>
          <ButtonLink href={`${href}?tab=commands`} icon={TerminalSquare}>
            Restart or run a command
          </ButtonLink>
        </>
      }
    >
      <div role="status" className={cx("flex items-start gap-3 rounded-lg px-4 py-3", tone.surface)}>
        <BannerIcon size={18} aria-hidden="true" className={cx("mt-0.5 shrink-0", tone.text)} />
        <p className="m-0 grid gap-0.5">
          <span className={cx("font-semibold", tone.text)}>{status.label}</span>
          <span className="text-(--slate)">{status.reason}.</span>
        </p>
      </div>
      <DefinitionList
        items={[
          { term: "Last seen", value: seen(item, now) },
          { term: "Signed in", value: item.logged_in_user ? <span className="font-(family-name:--font-data)">{item.logged_in_user}</span> : "Nobody" },
          { term: "Agent", value: formatAgentVersion(item.agent_version, "Unknown version") },
        ]}
      />
      <div className="grid gap-2.5">
        <h3 className="m-0 text-sm font-semibold text-(--ink)">Current readings</h3>
        {(
          [
            ["Processor", item.cpu_percent],
            ["Memory", item.mem_percent],
            ["Disk", item.disk_percent],
          ] as const
        ).map(([label, value]) => (
          <div key={label} className="grid grid-cols-[100px_1fr] items-center gap-3">
            <span className="text-[13px] text-(--muted)">{label}</span>
            <Meter value={value} label={label} />
          </div>
        ))}
      </div>
    </Drawer>
  );
}

const CHIPS: Array<{ label: string; status: EndpointStatusFilter | undefined; count: keyof Counts }> = [
  { label: "All", status: undefined, count: "all" },
  { label: "Online", status: "online", count: "online" },
  { label: "Offline", status: "offline", count: "offline" },
  { label: "Waiting", status: "pending", count: "pending" },
];

export function EndpointsView({ query, rows, total, pageSize, counts, alertsUnavailable, canEnroll, now: nowIso }: EndpointsViewProps) {
  const router = useRouter();
  const [selected, setSelected] = useState<EndpointRow | null>(null);
  const now = new Date(nowIso);
  const filtered = Boolean(query.status || query.search);

  const columns: Column<EndpointRow>[] = [
    {
      key: "device",
      header: "Device",
      cell: ({ item }) => (
        <span className="flex items-center gap-3">
          <DeviceIcon item={item} />
          <PrimaryCell mono title={item.hostname} sub={osLabel(item)} />
        </span>
      ),
    },
    {
      key: "status",
      header: "Status",
      cell: ({ status }) => (
        <span className="grid justify-items-start gap-1">
          <StatusBadge tone={status.tone}>{status.label}</StatusBadge>
          <span className="text-xs text-(--muted)">{status.reason}</span>
        </span>
      ),
    },
    { key: "site", header: "Site", cell: ({ item }) => <PrimaryCell title={item.site_name} sub={item.client_name} /> },
    { key: "seen", header: "Last seen", cell: ({ item }) => seen(item, now) },
    {
      key: "user",
      header: "Signed in",
      cell: ({ item }) => (item.logged_in_user ? <span className="font-(family-name:--font-data) text-[13px]">{item.logged_in_user}</span> : <span className="text-(--muted)">—</span>),
    },
    { key: "cpu", header: "Processor", cell: ({ item }) => <Meter value={item.cpu_percent} label={`Processor, ${item.hostname}`} /> },
    { key: "mem", header: "Memory", cell: ({ item }) => <Meter value={item.mem_percent} label={`Memory, ${item.hostname}`} /> },
    { key: "disk", header: "Disk", cell: ({ item }) => <Meter value={item.disk_percent} label={`Disk, ${item.hostname}`} /> },
  ];

  const state =
    rows === null ? (
      <ErrorState body="The device list could not be loaded" onRetry={() => router.refresh()} />
    ) : rows.length === 0 ? (
      filtered ? (
        <EmptyState title="No devices match" body="Try a different name, or clear the filters." actionLabel="Clear filters" onAction={() => router.push(endpointsHref(query, { status: undefined, search: undefined }))} />
      ) : (
        <EmptyState icon={Monitor} title="No devices yet" body="Devices appear here once the NodeLink agent is installed and enrolled." />
      )
    ) : undefined;

  return (
    <PageStack>
      <PageHeader
        breadcrumb={[{ label: "Devices" }, { label: "Endpoints" }]}
        title="Endpoints"
        description="Every computer and server we look after. On each page, devices that need attention are listed first."
        actions={
          canEnroll ? (
            <ButtonLink href="/enrollment" variant="primary" icon={Plus}>
              Add a device
            </ButtonLink>
          ) : null
        }
      />
      <StatRow>
        <StatTile icon={Monitor} label="All devices" tone="info" value={counts.all ?? "—"} sub={query.search ? `Matching “${query.search}”` : "Enrolled in NodeLink"} />
        <StatTile icon={Monitor} label="Online" tone="ok" value={counts.online ?? "—"} sub="Checking in" />
        <StatTile icon={WifiOff} label="Offline" tone={counts.offline ? "warn" : "ok"} value={counts.offline ?? "—"} sub="Not checking in" />
        <StatTile icon={Clock} label="Waiting" tone="info" value={counts.pending ?? "—"} sub="Enrolment not finished" />
      </StatRow>
      {alertsUnavailable ? (
        <p role="status" className="m-0 flex items-center gap-2 rounded-lg bg-(--amber-soft) px-4 py-3 text-sm text-[#89500b]">
          <CircleAlert size={16} aria-hidden="true" />
          Monitoring alerts could not be loaded, so no device is shown as critical right now. Nothing was changed.
        </p>
      ) : null}
      <DataTable
        caption="Devices"
        columns={columns}
        rows={rows ?? []}
        rowKey={({ item }) => item.id}
        rowLabel={({ item }) => `Preview ${item.hostname}`}
        onRowSelect={setSelected}
        state={state}
        minWidth={1080}
        filters={
          <FilterBar
            trailing={
              <Button icon={Download} onClick={() => exportCsv(rows ?? [], now)} disabled={!rows || rows.length === 0}>
                Export list
              </Button>
            }
          >
            <SearchForm query={query} />
            <div role="group" aria-label="Filter by status" className="flex flex-wrap gap-2">
              {CHIPS.map((chip) => (
                <FilterChip key={chip.label} href={endpointsHref(query, { status: chip.status })} selected={query.status === chip.status} count={counts[chip.count] ?? undefined}>
                  {chip.label}
                </FilterChip>
              ))}
            </div>
          </FilterBar>
        }
        footer={rows && rows.length > 0 ? <TableFooter shown={rows.length} total={total} sortNote="most urgent first on this page" pagination={<Pagination query={query} total={total} pageSize={pageSize} />} /> : null}
      />
      <DeviceDrawer row={selected} onClose={() => setSelected(null)} now={now} />
    </PageStack>
  );
}
