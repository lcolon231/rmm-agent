// SPDX-License-Identifier: AGPL-3.0-only

import Link from "next/link";
import { redirect } from "next/navigation";

import { OverviewView, type OverviewData } from "@/components/overview-view";
import { AppShell } from "@/components/shell/app-shell";
import { getApprovalRequests } from "@/lib/approvals";
import { getAuditEventPage } from "@/lib/audit";
import { getClientNavigation, type NavigationData } from "@/lib/client-navigation";
import { attentionDevices, indexOpenAlerts } from "@/lib/device-status-core";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getEndpointList, type EndpointListData } from "@/lib/endpoint-list";
import { getMonitoringAlerts } from "@/lib/monitoring";
import { compliancePercent, openAlertsBySeverity, recentActivity, waitingForApproval } from "@/lib/overview-core";
import { getComplianceSummary } from "@/lib/patch-compliance";

export const dynamic = "force-dynamic";

type HomePageProps = {
  searchParams: Promise<{ client?: string | string[]; site?: string | string[] }>;
};

function settled<T>(result: PromiseSettledResult<T>): T | null {
  return result.status === "fulfilled" ? result.value : null;
}

export default async function Home({ searchParams }: HomePageProps) {
  const session = await getDashboardSession();
  if (session.kind === "anonymous") {
    redirect("/login");
  }

  if (session.kind === "unavailable") {
    return (
      <main className="login-page">
        <section className="login-panel login-status" aria-labelledby="session-status-title">
          <span className="login-eyebrow">Session verification</span>
          <h1 id="session-status-title">Operations is temporarily unavailable</h1>
          <p>NodeLink could not verify your operator session. Your dashboard data remains protected. Try again shortly.</p>
          <Link className="login-link" href="/">Try again</Link>
        </section>
      </main>
    );
  }

  const query = await searchParams;
  const token = session.sessionToken;

  let navigation: NavigationData | null = null;
  let navigationError = false;
  try {
    navigation = await getClientNavigation(token);
  } catch {
    navigationError = true;
  }

  const requestedClientId = typeof query.client === "string" ? query.client : undefined;
  const requestedSiteId = typeof query.site === "string" ? query.site : undefined;
  const selectedClient = navigation?.items.find((client) => client.id === requestedClientId);
  const selectedSite = selectedClient?.sites.find((site) => site.id === requestedSiteId);
  const validSelection = (!requestedClientId && !requestedSiteId) || Boolean(selectedClient && (!requestedSiteId || selectedSite));
  // An unknown scope is still sent as asked, never widened to every client:
  // the server's tenant boundary decides, and the sidebar says it is unavailable.
  const clientId = requestedClientId;
  const siteId = requestedSiteId;
  const scope = { clientId, siteId };

  const [all, offline, online, alerts, compliance, approvals, audit] = await Promise.allSettled([
    getEndpointList(token, scope),
    getEndpointList(token, { ...scope, status: "offline" }),
    getEndpointList(token, { ...scope, status: "online" }),
    getMonitoringAlerts(token),
    getComplianceSummary(token, scope),
    getApprovalRequests(token),
    getAuditEventPage(token, { page: 1 }),
  ]);

  const allList = settled<EndpointListData>(all);
  const offlineList = settled<EndpointListData>(offline);
  const onlineList = settled<EndpointListData>(online);
  const alertList = settled(alerts);
  const alertIndex = indexOpenAlerts(alertList ?? []);
  const now = new Date();

  const hostnames = new Map<string, string>();
  for (const list of [allList, offlineList, onlineList]) for (const item of list?.items ?? []) hostnames.set(item.id, item.hostname);

  const complianceSummary = settled(compliance);
  const approvalList = settled(approvals);
  const auditPage = settled(audit);

  const data: OverviewData = {
    scopeName: selectedSite ? `${selectedClient?.name} · ${selectedSite.name}` : (selectedClient?.name ?? null),
    now: now.toISOString(),
    devices: allList && offlineList && onlineList ? { total: allList.total, online: onlineList.total, offline: offlineList.total } : null,
    attention: allList && offlineList ? attentionDevices([offlineList.items, allList.items, onlineList?.items ?? []], alertIndex, now) : null,
    alerts: alertList ? openAlertsBySeverity(alertList) : null,
    compliance: complianceSummary ? compliancePercent(complianceSummary) : "error",
    approvals: approvalList
      ? waitingForApproval(
          approvalList.filter((request) => (!clientId || request.client_id === clientId) && (!siteId || request.site_id === siteId)),
          session.operator.id,
          now,
        )
      : null,
    activity: auditPage ? recentActivity(auditPage.items, hostnames) : null,
  };

  return (
    <AppShell
      activePath="/"
      navigation={navigation}
      navigationError={navigationError}
      operator={session.operator}
      selectedClientId={clientId}
      selectedSiteId={siteId}
      selectionError={!validSelection}
      alertCount={data.alerts?.total}
    >
      <OverviewView data={data} />
    </AppShell>
  );
}
