// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { ChevronLeft, ChevronRight, CircleAlert, CircleCheck, FileDown, ShieldCheck, ShieldOff, TriangleAlert } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { PageHeader, PageStack } from "@/components/shell/page-header";
import { ButtonLink, buttonClass } from "@/components/ui/button";
import { cx, focusRing } from "@/components/ui/cx";
import { DataTable, PrimaryCell, TableFooter, type Column } from "@/components/ui/data-table";
import { DefinitionList, Drawer } from "@/components/ui/drawer";
import { FilterBar, FilterChip, SearchField } from "@/components/ui/filter-bar";
import { StatRow, StatTile } from "@/components/ui/stat-tile";
import { EmptyState, ErrorState } from "@/components/ui/states";
import { StatusBadge, toneStyles } from "@/components/ui/status-badge";
import { formatSeen } from "@/lib/device-status-core";
import { formatMonitoringTimestamp } from "@/lib/monitoring-core";
import type { ComplianceEndpoint, ComplianceListData, ComplianceState, ComplianceSummary } from "@/lib/patch-compliance-core";
import {
  COMPLIANCE_STATES,
  complianceExportHref,
  complianceReportHref,
  complianceStateView,
  compliantPercent,
  plural,
  type ComplianceQuery,
} from "@/lib/patch-compliance-view-core";

type PatchComplianceViewProps = {
  query: ComplianceQuery;
  summary: ComplianceSummary | null;
  /** Rows already ordered most urgent first. */
  report: ComplianceListData | null;
  pageSize: number;
  now: string;
};

function scanned(endpoint: ComplianceEndpoint, now: Date) {
  return endpoint.scanned_at ? formatSeen(endpoint.scanned_at, now) : "No trusted scan";
}

function SearchForm({ query }: { query: ComplianceQuery }) {
  // A plain GET form: works before hydration and keeps the scope and state.
  return (
    <form role="search" action="/patch-compliance" method="get" className="w-full max-w-[320px] min-w-[200px] flex-1">
      {query.clientId ? <input type="hidden" name="client_id" value={query.clientId} /> : null}
      {query.siteId ? <input type="hidden" name="site_id" value={query.siteId} /> : null}
      {query.state ? <input type="hidden" name="state" value={query.state} /> : null}
      <SearchField label="Search devices by name" name="search" maxLength={100} defaultValue={query.search ?? ""} placeholder="Search by device name" className="max-w-none" />
    </form>
  );
}

function Pagination({ query, total, pageSize }: { query: ComplianceQuery; total: number; pageSize: number }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const iconLink = "flex size-9 items-center justify-center rounded-lg border border-(--line-strong) bg-(--paper) text-(--slate) hover:bg-(--primary-tint)";
  const disabled = "flex size-9 items-center justify-center rounded-lg border border-(--line) bg-(--fog) text-(--muted)";
  return (
    <>
      {query.page > 1 ? (
        <Link href={complianceReportHref(query, { page: query.page - 1 })} aria-label="Previous page" rel="prev" className={cx(iconLink, focusRing)}>
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
        <Link href={complianceReportHref(query, { page: query.page + 1 })} aria-label="Next page" rel="next" className={cx(iconLink, focusRing)}>
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

function MissingUpdatesDrawer({ endpoint, onClose }: { endpoint: ComplianceEndpoint | null; onClose: () => void }) {
  if (!endpoint) return null;
  const view = complianceStateView(endpoint.state);
  const tone = toneStyles[view.tone];
  const BannerIcon = tone.icon;
  const href = `/endpoints/${encodeURIComponent(endpoint.agent_id)}`;
  return (
    <Drawer
      open
      onClose={onClose}
      context={`${endpoint.client_name} · ${endpoint.site_name}`}
      title={<span className="font-(family-name:--font-data)">{endpoint.hostname}</span>}
      sub="Missing updates"
      footer={
        <>
          <ButtonLink href={href} variant="primary">
            Open device
          </ButtonLink>
          <ButtonLink href={`${href}/inventory`}>See each missing update</ButtonLink>
        </>
      }
    >
      <div role="status" className={cx("flex items-start gap-3 rounded-lg px-4 py-3", tone.surface)}>
        <BannerIcon size={18} aria-hidden="true" className={cx("mt-0.5 shrink-0", tone.text)} />
        <p className="m-0 grid gap-0.5">
          <span className={cx("font-semibold", tone.text)}>{view.label}</span>
          <span className="text-(--slate)">{view.reason}.</span>
        </p>
      </div>
      <DefinitionList
        items={[
          { term: "Approved, missing", value: endpoint.approved_missing },
          { term: "Deferred by policy", value: endpoint.deferred_missing },
          { term: "Denied by policy", value: endpoint.denied_missing },
          { term: "All missing", value: endpoint.total_missing },
          { term: "Latest trusted scan", value: endpoint.scanned_at ? formatMonitoringTimestamp(endpoint.scanned_at) : "No trusted scan" },
          {
            term: "Patch policy",
            value: endpoint.policy_id ? <span className="font-(family-name:--font-data) text-[13px]">{endpoint.policy_id}</span> : "None applies",
          },
        ]}
      />
      <p className="m-0 text-[13px] text-(--muted)">
        Counts come from the latest trusted Windows Update scan. The names of each missing update are listed on the device&apos;s inventory page.
      </p>
    </Drawer>
  );
}

export function PatchComplianceView({ query, summary, report, pageSize, now: nowIso }: PatchComplianceViewProps) {
  const router = useRouter();
  const [selected, setSelected] = useState<ComplianceEndpoint | null>(null);
  const now = new Date(nowIso);
  const filtered = Boolean(query.state || query.search);
  const percent = summary ? compliantPercent(summary) : null;
  const scope = { clientId: query.clientId, siteId: query.siteId, state: query.state };
  const unverified = summary ? summary.stale + summary.unknown : null;

  const columns: Column<ComplianceEndpoint>[] = [
    { key: "device", header: "Device", cell: (row) => <PrimaryCell mono title={row.hostname} sub={`${row.client_name} · ${row.site_name}`} /> },
    {
      key: "state",
      header: "Compliance",
      cell: (row) => {
        const view = complianceStateView(row.state);
        return (
          <span className="grid justify-items-start gap-1">
            <StatusBadge tone={view.tone}>{view.label}</StatusBadge>
            <span className="text-xs text-(--muted)">{view.reason}</span>
          </span>
        );
      },
    },
    {
      key: "approved",
      header: "Approved, missing",
      align: "end",
      cell: (row) => <span className={cx("tabular-nums", row.approved_missing > 0 ? "font-semibold text-[#89500b]" : undefined)}>{row.approved_missing}</span>,
    },
    { key: "other", header: "Other missing", cell: (row) => `${row.deferred_missing} deferred · ${row.denied_missing} denied` },
    { key: "scan", header: "Last scan", cell: (row) => scanned(row, now) },
  ];

  const state =
    report === null ? (
      <ErrorState body="The compliance report could not be loaded, so no devices are shown" onRetry={() => router.refresh()} />
    ) : report.items.length === 0 ? (
      filtered ? (
        <EmptyState title="No devices match" body="Try a different name, or clear the filters." actionLabel="Clear filters" onAction={() => router.push(complianceReportHref(query, { state: undefined, search: undefined }))} />
      ) : (
        <EmptyState icon={ShieldCheck} title="No devices in this report" body="No managed devices are available in this scope." />
      )
    ) : undefined;

  return (
    <PageStack>
      <PageHeader
        breadcrumb={[{ label: "Patching" }, { label: "Patch compliance" }]}
        title="Patch compliance"
        description="Which devices have every approved update installed, and which are behind. This report cannot install or approve updates."
        actions={
          <>
            {/* Plain anchors: the export is a file download from an API route, not a page. */}
            <a href={complianceExportHref("json", scope)} className={buttonClass("secondary")}>
              Download as JSON
            </a>
            <a href={complianceExportHref("csv", scope)} className={buttonClass("primary")}>
              <FileDown size={16} aria-hidden="true" />
              Export evidence report
            </a>
          </>
        }
      />
      <StatRow>
        <StatTile
          icon={ShieldCheck}
          label="Compliant"
          tone={summary === null || percent === null ? "off" : percent === 100 ? "ok" : "warn"}
          value={percent === null ? "—" : `${percent}%`}
          sub={summary ? `${summary.compliant} of ${plural(summary.total_endpoints, "device")}` : "Could not be counted"}
        />
        <StatTile
          icon={TriangleAlert}
          label="Behind"
          tone={summary?.non_compliant ? "warn" : summary ? "ok" : "off"}
          value={summary?.non_compliant ?? "—"}
          sub={summary ? `${plural(summary.total_approved_missing, "approved update")} missing` : "Could not be counted"}
        />
        <StatTile
          icon={CircleAlert}
          label="Not verified"
          tone={unverified ? "warn" : summary ? "ok" : "off"}
          value={unverified ?? "—"}
          sub={summary ? `${summary.stale} out of date · ${summary.unknown} without a trusted scan` : "Could not be counted"}
        />
        <StatTile icon={ShieldOff} label="Exempt" tone="off" value={summary?.exempt ?? "—"} sub="No patch policy applies" />
      </StatRow>
      {summary === null ? (
        <p role="alert" className="m-0 flex items-center gap-2 rounded-lg bg-(--amber-soft) px-4 py-3 text-sm text-[#89500b]">
          <TriangleAlert size={16} aria-hidden="true" />
          Summary counts could not be verified. The device list below may still be available. Nothing was changed.
        </p>
      ) : null}
      {summary?.truncated || report?.truncated ? (
        <p role="status" className="m-0 flex items-center gap-2 rounded-lg bg-(--amber-soft) px-4 py-3 text-sm text-[#89500b]">
          <TriangleAlert size={16} aria-hidden="true" />
          The configured device limit was reached. Counts and exports cover only the devices that were counted.
        </p>
      ) : null}
      <p className="m-0 flex items-start gap-2 text-[13px] text-(--muted)">
        <CircleCheck size={16} aria-hidden="true" className="mt-0.5 shrink-0" />
        A device is behind only when an update its policy approves is still missing. Old scans need review, devices without a trusted scan are unknown, and devices without a policy are exempt.
      </p>
      <DataTable
        caption="Patch compliance by device"
        columns={columns}
        rows={report?.items ?? []}
        rowKey={(row) => row.agent_id}
        rowLabel={(row) => `Show missing updates for ${row.hostname}`}
        onRowSelect={setSelected}
        state={state}
        minWidth={900}
        filters={
          <FilterBar>
            <SearchForm query={query} />
            <div role="group" aria-label="Filter by compliance" className="flex flex-wrap gap-2">
              <FilterChip href={complianceReportHref(query, { state: undefined })} selected={!query.state} count={summary?.total_endpoints}>
                All
              </FilterChip>
              {COMPLIANCE_STATES.map((item: ComplianceState) => (
                <FilterChip key={item} href={complianceReportHref(query, { state: item })} selected={query.state === item} count={summary?.[item]}>
                  {complianceStateView(item).label}
                </FilterChip>
              ))}
            </div>
          </FilterBar>
        }
        footer={
          report && report.items.length > 0 ? (
            <TableFooter shown={report.items.length} total={report.total} sortNote="most urgent first on this page" pagination={<Pagination query={query} total={report.total} pageSize={pageSize} />} />
          ) : null
        }
      />
      <MissingUpdatesDrawer endpoint={selected} onClose={() => setSelected(null)} />
    </PageStack>
  );
}
