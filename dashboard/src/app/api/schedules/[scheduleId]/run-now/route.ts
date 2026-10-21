// SPDX-License-Identifier: AGPL-3.0-only

import { getDashboardSession } from "@/lib/dashboard-session";
import { runScheduledTaskNow } from "@/lib/scheduled-tasks";
import { handleRunScheduleNow } from "@/lib/schedules-route-core";

export const dynamic = "force-dynamic";

export async function POST(
  request: Request,
  { params }: { params: Promise<{ scheduleId: string }> },
) {
  const { scheduleId } = await params;
  return handleRunScheduleNow(request, scheduleId, {
    getSession: getDashboardSession,
    runScheduledTaskNow,
  });
}
