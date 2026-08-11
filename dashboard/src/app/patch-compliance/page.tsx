// SPDX-License-Identifier: AGPL-3.0-only

import {
  ChevronLeft,
  ChevronRight,
  Download,
  Filter,
  ListChecks,
  ShieldCheck,
} from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";

import { getDashboardSession } from "@/lib/dashboard-session";
import { formatMonitoringTimestamp } from "@/lib/monitoring-core";
import {
  formatComplianceState,
  type ComplianceListData,
  type ComplianceState,
  type ComplianceSummary,
} from "@/lib/patch-compliance-core";
import { getComplianceList, getComplianceSummary } from "@/lib/patch-compliance";

export const dynamic = "force-dynamic";

const PAGE_SIZE = 25;
const STATES: ComplianceState[] = [
  "compliant",
  "non_compliant",
  "stale",
  "unknown",
  "exempt",
];

type SearchParams = {
  client_id?: string;
  page?: string;
  search?: string;
  site_id?: string;
  state?: string;
};

function complianceState(value: string | undefined): ComplianceState | undefined {
  return STATES.find((state) => state === value);
}

function reportHref(
  params: {
    clientId?: string;
    page: number;
    search?: string;
    siteId?: string;
    state?: ComplianceState;
  },
  page: number,
): string {
  const query = new URLSearchParams();
  if (params.clientId) query.set("client_id", params.clientId);
  if (params.siteId) query.set("site_id", params.siteId);
  if (params.state) query.set("state", params.state);
  if (params.search) query.set("search", params.search);
  if (page > 1) query.set("page", String(page));
  const suffix = query.size > 0 ? `?${query}` : "";
  return `/patch-compliance${suffix}`;
}

function exportHref(
  format: "csv" | "json",
  scope: { clientId?: string; siteId?: string; state?: ComplianceState },
): string {
  const query = new URLSearchParams({ format });
  if (scope.clientId) query.set("client_id", scope.clientId);
  if (scope.siteId) query.set("site_id", scope.siteId);
  if (scope.state) query.set("state", scope.state);
  return `/api/patch-compliance/export?${query}`;
}

export default async function PatchCompliancePage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  const raw = await searchParams;
  const requestedPage = typeof raw.page === "string" ? Number(raw.page) : 1;
  const page = Number.isInteger(requestedPage) && requestedPage >= 1 ? requestedPage : 1;
  const clientId = raw.client_id?.trim() || undefined;
  const siteId = raw.site_id?.trim() || undefined;
  const state = complianceState(raw.state);
  const search = raw.search?.trim() || undefined;
  const scope = { clientId, siteId };

  let summary: ComplianceSummary | null = null;
  let report: ComplianceListData | null = null;
  const [summaryResult, reportResult] = await Promise.allSettled([
    getComplianceSummary(session.sessionToken, scope),
    getComplianceList(session.sessionToken, {
      ...scope,
      state,
      search,
      page,
      pageSize: PAGE_SIZE,
    }),
  ]);
  if (summaryResult.status === "fulfilled") summary = summaryResult.value;
  if (reportResult.status === "fulfilled") report = reportResult.value;

  const pageCount = Math.max(1, Math.ceil((report?.total ?? 0) / PAGE_SIZE));
  const query = { ...scope, page, search, state };
  const filtered = Boolean(state || search);
  const summaryCards = summary === null ? [] : STATES.map((item) => ({
    state: item,
    value: summary[item],
  }));

  return (
    <>
      <header className="enrollment-page-head">
        <div>
          <span>Current policy posture</span>
          <h1>Patch compliance</h1>
          <p>
            Endpoint status derived from the latest trusted Windows Update scan and the effective
            approval policy. This report cannot install, approve, or change an update.
          </p>
        </div>
        <span className="monitoring-readonly-note">Read-only report</span>
      </header>

      {summary === null ? (
        <div className="compliance-summary-unavailable" role="alert">
          Summary counts could not be verified. The endpoint register may still be available below.
        </div>
      ) : (
        <section className="compliance-summary-grid" aria-label="Compliance summary">
          {summaryCards.map((card) => (
            <article className={card.state} key={card.state}>
              <span>{formatComplianceState(card.state)}</span>
              <strong>{card.value}</strong>
              <small>endpoint{card.value === 1 ? "" : "s"}</small>
            </article>
          ))}
        </section>
      )}

      <section className="setup-boundary-banner compliance-boundary-banner">
        <ShieldCheck aria-hidden="true" size={22} />
        <div>
          <strong>
            {summary === null
              ? "Policy evaluation is unavailable"
              : `${summary.total_approved_missing} approved update${summary.total_approved_missing === 1 ? "" : "s"} still missing`}
          </strong>
          <span>
            Fresh endpoints are non-compliant only when a policy-approved update remains missing.
            Old scans are stale, untrusted or absent scans are unknown, and endpoints without an
            effective policy are exempt.
          </span>
        </div>
      </section>

      <div className="compliance-toolbar">
        <form className="enrollment-filter audit-filter" method="get">
          {clientId ? <input name="client_id" type="hidden" value={clientId} /> : null}
          {siteId ? <input name="site_id" type="hidden" value={siteId} /> : null}
          <label>
            <Filter aria-hidden="true" size={16} />
            <span className="sr-only">Filter by compliance state</span>
            <select defaultValue={state ?? ""} name="state">
              <option value="">All states</option>
              {STATES.map((item) => (
                <option key={item} value={item}>{formatComplianceState(item)}</option>
              ))}
            </select>
          </label>
          <label>
            <span className="sr-only">Search endpoint hostname</span>
            <input defaultValue={search ?? ""} name="search" placeholder="Endpoint hostname…" type="search" />
          </label>
          <button type="submit">Apply</button>
          {filtered ? <Link className="audit-filter-clear" href={reportHref({ ...query, state: undefined, search: undefined }, 1)}>Clear</Link> : null}
        </form>
        <div className="compliance-export-actions" aria-label="Export report">
          <a href={exportHref("csv", { ...scope, state })}><Download size={14} /> CSV</a>
          <a href={exportHref("json", { ...scope, state })}><Download size={14} /> JSON</a>
        </div>
      </div>

      {summary?.truncated || report?.truncated ? (
        <p className="compliance-truncated" role="status">
          The configured endpoint limit was reached. Counts and exports cover only the bounded result set.
        </p>
      ) : null}

      <section className="enrollment-panel">
        <header>
          <div>
            <span>Endpoint register</span>
            <h2>{report === null ? "Unavailable" : `${report.total} endpoint${report.total === 1 ? "" : "s"}`}</h2>
            {report === null ? null : <small>Page {report.page} of {pageCount} · {PAGE_SIZE} per page</small>}
          </div>
          <ListChecks aria-hidden="true" size={19} />
        </header>

        {report === null ? (
          <div className="enrollment-empty" role="alert">
            <ListChecks size={24} />
            <h3>Patch compliance could not be loaded</h3>
            <p>No endpoint rows are shown because the server response could not be verified.</p>
          </div>
        ) : report.items.length === 0 ? (
          <div className="enrollment-empty">
            <ListChecks size={24} />
            <h3>No endpoints match this report</h3>
            <p>{filtered ? "Clear or widen the filters to see more endpoints." : "No managed endpoints are available in this scope."}</p>
          </div>
        ) : (
          <div className="enrollment-table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Endpoint</th>
                  <th>Client / site</th>
                  <th>State</th>
                  <th>Approved missing</th>
                  <th>Other missing</th>
                  <th>Latest scan (UTC)</th>
                </tr>
              </thead>
              <tbody>
                {report.items.map((endpoint) => (
                  <tr key={endpoint.agent_id}>
                    <td>
                      <Link href={`/endpoints/${encodeURIComponent(endpoint.agent_id)}`}>{endpoint.hostname}</Link>
                      <code>{endpoint.agent_id}</code>
                    </td>
                    <td><strong>{endpoint.client_name}</strong><code>{endpoint.site_name}</code></td>
                    <td><span className={`compliance-state-chip ${endpoint.state}`}>{formatComplianceState(endpoint.state)}</span></td>
                    <td><strong className={endpoint.approved_missing > 0 ? "compliance-missing-count" : undefined}>{endpoint.approved_missing}</strong></td>
                    <td>{endpoint.deferred_missing} deferred · {endpoint.denied_missing} denied</td>
                    <td>{endpoint.scanned_at ? formatMonitoringTimestamp(endpoint.scanned_at) : "No trusted scan"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {report === null || report.items.length === 0 ? null : (
          <footer className="enrollment-pagination">
            <span>Showing {report.items.length} of {report.total} endpoint{report.total === 1 ? "" : "s"}</span>
            <span className="audit-pager">
              {report.page > 1 ? (
                <Link href={reportHref(query, report.page - 1)} rel="prev"><ChevronLeft size={14} /> Previous</Link>
              ) : null}
              {report.page < pageCount ? (
                <Link href={reportHref(query, report.page + 1)} rel="next">Next <ChevronRight size={14} /></Link>
              ) : null}
            </span>
          </footer>
        )}
      </section>
    </>
  );
}
