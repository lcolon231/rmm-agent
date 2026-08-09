// SPDX-License-Identifier: AGPL-3.0-only

import { ChevronLeft, ChevronRight, Filter, ListChecks } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";

import { describeCommandStatus, type CommandStatus } from "@/lib/command-console-core";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getTaskRuns } from "@/lib/task-runs";
import {
  asCommandKind,
  asCommandStatus,
  formatTaskRunTimestamp,
  hasTaskRunFilters,
  taskRunPageCount,
  taskRunPageHref,
  type TaskRunFilters,
  type TaskRunHistoryData,
} from "@/lib/task-runs-core";

export const dynamic = "force-dynamic";

const PAGE_SIZE = 25;

const STATUS_OPTIONS: CommandStatus[] = [
  "queued",
  "dispatched",
  "running",
  "result_pending",
  "succeeded",
  "failed",
  "expired",
];

type SearchParams = {
  page?: string;
  agent_id?: string;
  status?: string;
  kind?: string;
  from?: string;
  to?: string;
};

export default async function TasksPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  const params = await searchParams;
  const requestedPage = typeof params.page === "string" ? Number(params.page) : 1;
  const page = Number.isInteger(requestedPage) && requestedPage >= 1 ? requestedPage : 1;
  const filters: TaskRunFilters = {
    agentId: params.agent_id?.trim() || undefined,
    status: asCommandStatus(params.status),
    kind: asCommandKind(params.kind),
    from: params.from?.trim() || undefined,
    to: params.to?.trim() || undefined,
  };

  let history: TaskRunHistoryData | null = null;
  try {
    history = await getTaskRuns(session.sessionToken, { page, pageSize: PAGE_SIZE, filters });
  } catch {
    history = null;
  }

  const pageCount = history === null ? 1 : taskRunPageCount(history.total, PAGE_SIZE);
  const filtered = hasTaskRunFilters(filters);

  return (
    <>
      <header className="enrollment-page-head">
        <div>
          <span>Complete run provenance</span>
          <h1>Task history</h1>
          <p>
            Every command dispatched to any endpoint, newest first, with the operator who ran it and
            its script-library origin. Open a run for its signed envelope and captured output.
          </p>
        </div>
      </header>

      <form className="enrollment-filter audit-filter" method="get">
        <label>
          <Filter size={16} />
          <span className="sr-only">Filter by status</span>
          <select defaultValue={filters.status ?? ""} name="status">
            <option value="">All statuses</option>
            {STATUS_OPTIONS.map((status) => (
              <option key={status} value={status}>
                {describeCommandStatus(status).label}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="sr-only">Filter by kind</span>
          <select defaultValue={filters.kind ?? ""} name="kind">
            <option value="">All kinds</option>
            <option value="powershell">PowerShell</option>
            <option value="shell">Shell</option>
            <option value="collect_inventory">Collect inventory</option>
            <option value="reboot">Restart endpoint</option>
            <option value="shutdown">Shut down endpoint</option>
            <option value="cancel_power_action">Cancel power action</option>
          </select>
        </label>
        <label>
          <span className="sr-only">Filter by endpoint (agent ID)</span>
          <input defaultValue={filters.agentId ?? ""} name="agent_id" placeholder="Agent ID" type="search" />
        </label>
        <label>
          <span className="sr-only">Runs from date (UTC)</span>
          <input defaultValue={filters.from ?? ""} name="from" type="date" />
        </label>
        <label>
          <span className="sr-only">Runs to date (UTC)</span>
          <input defaultValue={filters.to ?? ""} name="to" type="date" />
        </label>
        <button type="submit">Apply</button>
        {filtered ? <Link className="audit-filter-clear" href="/tasks">Clear</Link> : null}
      </form>

      <section className="enrollment-panel">
        <header>
          <div>
            <span>Task-run register</span>
            <h2>{history === null ? "Unavailable" : `${history.total} run${history.total === 1 ? "" : "s"}`}</h2>
            {history === null ? null : (
              <small>Page {history.page} of {pageCount} · {PAGE_SIZE} per page</small>
            )}
          </div>
          <ListChecks size={19} />
        </header>

        {history === null ? (
          <div className="enrollment-empty" role="alert">
            <ListChecks size={24} />
            <h3>Task history could not be loaded</h3>
            <p>No runs are shown because the response could not be verified. This is not evidence that no runs exist.</p>
          </div>
        ) : history.items.length === 0 ? (
          <div className="enrollment-empty">
            <ListChecks size={24} />
            <h3>No runs match these filters</h3>
            <p>{filtered ? "Clear or widen the filters to see more runs." : "No commands have been dispatched yet."}</p>
          </div>
        ) : (
          <div className="enrollment-table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Run</th>
                  <th>Endpoint</th>
                  <th>Kind</th>
                  <th>Status</th>
                  <th>Actor</th>
                  <th>Origin</th>
                  <th>Dispatched (UTC)</th>
                </tr>
              </thead>
              <tbody>
                {history.items.map((run) => {
                  const presentation = describeCommandStatus(run.status);
                  return (
                    <tr key={run.id}>
                      <td>
                        <Link href={`/endpoints/${encodeURIComponent(run.agent_id)}/commands/${encodeURIComponent(run.id)}`}>
                          {run.id}
                        </Link>
                      </td>
                      <td>
                        {run.hostname ?? "Unknown host"}
                        <code>{run.agent_id}</code>
                      </td>
                      <td>{run.kind}</td>
                      <td><span className={`command-status ${presentation.tone}`}>{presentation.label}</span></td>
                      <td>{run.actor_email ?? "Not recorded"}</td>
                      <td>{run.script_version_id ? <code>script {run.script_version_id}</code> : "Ad-hoc"}</td>
                      <td>{formatTaskRunTimestamp(run.dispatched_at ?? run.created_at)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {history === null || history.items.length === 0 ? null : (
          <footer className="enrollment-pagination">
            <span>Showing {history.items.length} of {history.total} run{history.total === 1 ? "" : "s"}</span>
            <span className="audit-pager">
              {history.page > 1 ? (
                <Link href={taskRunPageHref(filters, history.page - 1)} rel="prev"><ChevronLeft size={14} /> Newer</Link>
              ) : null}
              {history.page < pageCount ? (
                <Link href={taskRunPageHref(filters, history.page + 1)} rel="next">Older <ChevronRight size={14} /></Link>
              ) : null}
            </span>
          </footer>
        )}
      </section>
    </>
  );
}
