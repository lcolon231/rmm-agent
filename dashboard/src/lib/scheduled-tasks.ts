// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import {
  scheduledTaskListFromUnknown,
  type ScheduledTaskListData,
} from "@/lib/scheduled-tasks-core";
import { nodelinkApiRequest } from "@/lib/nodelink-api";

export async function getScheduledTasks(
  sessionToken: string,
  options: { page?: number; pageSize?: number } = {},
): Promise<ScheduledTaskListData> {
  const query = new URLSearchParams({
    page: String(options.page ?? 1),
    page_size: String(options.pageSize ?? 50),
  });

  const value = await nodelinkApiRequest<unknown>(
    `/api/v1/scheduled-tasks?${query}`,
    { method: "GET", sessionToken },
  );
  const data = scheduledTaskListFromUnknown(value);
  if (!data) {
    throw new Error("The management service returned invalid scheduled tasks data.");
  }
  return data;
}
