// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";

import { SchedulesView } from "@/components/schedules/schedules-view";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getScheduledTasks } from "@/lib/scheduled-tasks";
import type { ScheduledTaskListData } from "@/lib/scheduled-tasks-core";

export const dynamic = "force-dynamic";

export default async function SchedulesPage() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  let schedules: ScheduledTaskListData | null = null;
  try {
    const loaded = await getScheduledTasks(session.sessionToken);
    // The view is a client component and never shows the command payload, so
    // the script text is not sent to the browser.
    schedules = { ...loaded, items: loaded.items.map((item) => ({ ...item, payload: {} })) };
  } catch {
    schedules = null;
  }

  return <SchedulesView schedules={schedules} role={session.operator.role} />;
}
