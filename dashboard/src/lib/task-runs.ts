// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import {
  taskRunHistoryFromUnknown,
  type TaskRunFilters,
  type TaskRunHistoryData,
} from "@/lib/task-runs-core";
import { nodelinkApiRequest } from "@/lib/nodelink-api";

export async function getTaskRuns(
  sessionToken: string,
  options: { page?: number; pageSize?: number; filters?: TaskRunFilters } = {},
): Promise<TaskRunHistoryData> {
  const query = new URLSearchParams({
    page: String(options.page ?? 1),
    page_size: String(options.pageSize ?? 25),
  });
  const filters = options.filters ?? {};
  if (filters.agentId) query.set("agent_id", filters.agentId);
  if (filters.status) query.set("status", filters.status);
  if (filters.kind) query.set("kind", filters.kind);
  if (filters.from) query.set("from", filters.from);
  if (filters.to) query.set("to", filters.to);

  const value = await nodelinkApiRequest<unknown>(
    `/api/v1/task-runs?${query}`,
    { method: "GET", sessionToken },
  );
  const history = taskRunHistoryFromUnknown(value);
  if (!history) {
    throw new Error("The management service returned invalid task-run history.");
  }
  return history;
}
