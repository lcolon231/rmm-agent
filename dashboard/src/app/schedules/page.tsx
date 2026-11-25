// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";

import { SchedulesView } from "@/components/schedules/schedules-view";
import { getClientNavigation } from "@/lib/client-navigation";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getEndpointList } from "@/lib/endpoint-list";
import { getScheduledTasks } from "@/lib/scheduled-tasks";
import type { ScheduledTaskListData } from "@/lib/scheduled-tasks-core";
import { siteOptionGroups, type ScheduleOption, type ScheduleSources } from "@/lib/schedule-form-core";
import { listScripts } from "@/lib/script-library";

export const dynamic = "force-dynamic";

/** The endpoint picker pages through what the operator can see, capped so a
 * very large fleet cannot stall the page. */
const ENDPOINT_PAGE_LIMIT = 10;

async function loadEndpoints(sessionToken: string): Promise<ScheduleOption[]> {
  const endpoints: ScheduleOption[] = [];
  for (let page = 1; page <= ENDPOINT_PAGE_LIMIT; page += 1) {
    const loaded = await getEndpointList(sessionToken, { page, pageSize: 100, sort: "hostname", direction: "asc" });
    endpoints.push(...loaded.items.map((item) => ({ id: item.id, label: item.hostname })));
    if (endpoints.length >= loaded.total || loaded.items.length === 0) break;
  }
  return endpoints;
}

function valueOrNull<T>(result: PromiseSettledResult<T>): T | null {
  return result.status === "fulfilled" ? result.value : null;
}

export default async function SchedulesPage() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");
  const token = session.sessionToken;

  const [loaded, scripts, navigation, endpoints] = await Promise.allSettled([
    getScheduledTasks(token),
    listScripts(token),
    getClientNavigation(token),
    loadEndpoints(token),
  ]);

  let schedules: ScheduledTaskListData | null = null;
  if (loaded.status === "fulfilled") {
    // The view is a client component and never shows the command payload, so
    // the script text is not sent to the browser.
    schedules = { ...loaded.value, items: loaded.value.items.map((item) => ({ ...item, payload: {} })) };
  }
  const nav = valueOrNull(navigation);
  const sources: ScheduleSources = {
    scripts: valueOrNull(scripts)?.items ?? null,
    sites: nav ? siteOptionGroups(nav) : null,
    endpoints: valueOrNull(endpoints),
  };

  return <SchedulesView schedules={schedules} role={session.operator.role} sources={sources} />;
}
