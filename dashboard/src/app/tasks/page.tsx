// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";

import { TaskRunsView } from "@/components/automation/task-runs-view";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getTaskRuns } from "@/lib/task-runs";
import {
  asCommandKind,
  asCommandStatus,
  hasTaskRunFilters,
  taskRunPageCount,
  type TaskRunFilters,
  type TaskRunHistoryData,
} from "@/lib/task-runs-core";

export const dynamic = "force-dynamic";

const PAGE_SIZE = 25;

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

  return (
    <TaskRunsView
      history={history}
      filters={filters}
      filtered={hasTaskRunFilters(filters)}
      pageSize={PAGE_SIZE}
      pageCount={history === null ? 1 : taskRunPageCount(history.total, PAGE_SIZE)}
    />
  );
}
