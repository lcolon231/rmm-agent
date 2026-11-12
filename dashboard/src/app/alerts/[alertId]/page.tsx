// SPDX-License-Identifier: AGPL-3.0-only

import { notFound, redirect } from "next/navigation";

import { AlertDetailView } from "@/components/alerts/alert-detail-view";
import { getDashboardSession } from "@/lib/dashboard-session";
import {
  getAlertAssignees,
  getAlertEmailDeliveries,
  getAlertWebhookDeliveries,
  getMonitoringAlert,
} from "@/lib/monitoring";
import { parseAlertTab } from "@/lib/monitoring-view-core";
import { NodelinkApiError } from "@/lib/nodelink-api";

export const dynamic = "force-dynamic";

export default async function AlertDetailPage({
  params,
  searchParams,
}: {
  params: Promise<{ alertId: string }>;
  searchParams?: Promise<{ tab?: string | string[] }>;
}) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");
  const { alertId } = await params;
  const tab = parseAlertTab((await searchParams)?.tab);
  let alert;
  let deliveries;
  let webhookDeliveries;
  let assignees;
  try {
    [alert, deliveries, webhookDeliveries, assignees] = await Promise.all([
      getMonitoringAlert(session.sessionToken, alertId),
      getAlertEmailDeliveries(session.sessionToken, alertId),
      getAlertWebhookDeliveries(session.sessionToken, alertId),
      session.operator.role === "readonly"
        ? Promise.resolve([])
        : getAlertAssignees(session.sessionToken).catch(() => []),
    ]);
  } catch (error) {
    if (error instanceof NodelinkApiError && error.status === 404) notFound();
    throw error;
  }

  return (
    <AlertDetailView
      alert={alert}
      emailDeliveries={deliveries}
      webhookDeliveries={webhookDeliveries}
      assignees={assignees}
      canManage={session.operator.role !== "readonly"}
      tab={tab}
    />
  );
}
