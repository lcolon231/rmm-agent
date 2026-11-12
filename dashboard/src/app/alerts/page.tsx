// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";

import { AlertsView, type AlertCounts } from "@/components/alerts/alerts-view";
import { getDashboardSession } from "@/lib/dashboard-session";
import type { MonitoringAlert } from "@/lib/monitoring-core";
import { getMonitoringAlerts } from "@/lib/monitoring";
import { ALERT_FILTERS, alertMatchesFilter, parseAlertFilter, sortAlertsByRisk } from "@/lib/monitoring-view-core";

export const dynamic = "force-dynamic";

type AlertsPageProps = {
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
};

export default async function AlertsPage({ searchParams }: AlertsPageProps) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  const filter = parseAlertFilter((await searchParams)?.filter);
  let alerts: MonitoringAlert[] | null = null;
  const alertResult = await Promise.allSettled([getMonitoringAlerts(session.sessionToken)]);
  if (alertResult[0].status === "fulfilled") alerts = alertResult[0].value;

  const counts: AlertCounts | null = alerts
    ? (Object.fromEntries(ALERT_FILTERS.map((name) => [name, alerts.filter((alert) => alertMatchesFilter(alert, name)).length])) as AlertCounts)
    : null;
  const unassigned = alerts ? alerts.filter((alert) => alert.state !== "resolved" && !alert.assigned_to_operator_id).length : null;
  const rows = alerts ? sortAlertsByRisk(alerts.filter((alert) => alertMatchesFilter(alert, filter))) : null;

  return <AlertsView filter={filter} rows={rows} loaded={alerts?.length ?? 0} counts={counts} unassigned={unassigned} />;
}
