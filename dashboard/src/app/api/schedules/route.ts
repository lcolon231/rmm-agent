// SPDX-License-Identifier: AGPL-3.0-only

import { getDashboardSession } from "@/lib/dashboard-session";
import { createScheduledTask } from "@/lib/scheduled-tasks";
import { handleCreateSchedule } from "@/lib/schedules-route-core";

export const dynamic = "force-dynamic";

export function POST(request: Request) {
  return handleCreateSchedule(request, {
    createScheduledTask,
    getSession: getDashboardSession,
  });
}
