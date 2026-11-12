// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";

import { EndpointsView, type EndpointRow } from "@/components/endpoints-view";
import { getDashboardSession } from "@/lib/dashboard-session";
import { deviceStatus, indexOpenAlerts, riskRank } from "@/lib/device-status-core";
import { getEndpointList, type EndpointQuery } from "@/lib/endpoint-list";
import { parseEndpointsQuery } from "@/lib/endpoints-list-core";
import { getMonitoringAlerts } from "@/lib/monitoring";

export const dynamic = "force-dynamic";

type EndpointsPageProps = {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
};

export default async function EndpointsPage({ searchParams }: EndpointsPageProps) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  const query = parseEndpointsQuery(await searchParams);
  const token = session.sessionToken;
  const base: EndpointQuery = { clientId: query.client, siteId: query.site, search: query.search };
  const count = (status?: EndpointQuery["status"]) => getEndpointList(token, { ...base, status, pageSize: 1 }).then((list) => list.total);

  const [list, all, online, offline, pending, alerts] = await Promise.allSettled([
    getEndpointList(token, { ...base, status: query.status, page: query.page, sort: "last_seen", direction: "desc" }),
    count(),
    count("online"),
    count("offline"),
    count("pending"),
    getMonitoringAlerts(token),
  ]);

  const now = new Date();
  // Without alerts nothing can be called critical, so the page says so rather than guessing.
  const alertIndex = indexOpenAlerts(alerts.status === "fulfilled" ? alerts.value : []);
  const rows: EndpointRow[] | null =
    list.status === "fulfilled"
      ? list.value.items
          .map((item, index) => ({ item, status: deviceStatus(item, alertIndex, now), index }))
          .sort((a, b) => riskRank(a.status.tone) - riskRank(b.status.tone) || a.index - b.index)
          .map(({ item, status }) => ({ item, status }))
      : null;

  const value = (result: PromiseSettledResult<number>) => (result.status === "fulfilled" ? result.value : null);

  return (
    <EndpointsView
      query={query}
      rows={rows}
      total={list.status === "fulfilled" ? list.value.total : 0}
      pageSize={list.status === "fulfilled" ? list.value.page_size : 25}
      counts={{ all: value(all), online: value(online), offline: value(offline), pending: value(pending) }}
      alertsUnavailable={alerts.status === "rejected"}
      canEnroll={session.operator.role !== "readonly"}
      now={now.toISOString()}
    />
  );
}
