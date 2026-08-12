// SPDX-License-Identifier: AGPL-3.0-only

import { DashboardShell } from "@/components/dashboard-shell";
import { getAuditAnchors, getAuditEventPage, verifyAuditChain } from "@/lib/audit";
import type { AuditAnchorRecord, AuditChainVerification, AuditEventRecord } from "@/lib/audit-core";
import { getClientNavigation, type NavigationData } from "@/lib/client-navigation";
import { getSigningKeys } from "@/lib/dashboard-overview";
import type { SigningKeyInfo } from "@/lib/dashboard-overview-core";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getEndpointList, type EndpointListData } from "@/lib/endpoint-list";
import { getMonitoringAlerts } from "@/lib/monitoring";
import type { MonitoringAlert } from "@/lib/monitoring-core";
import Link from "next/link";
import { redirect } from "next/navigation";

export const dynamic = "force-dynamic";

type HomePageProps = {
  searchParams: Promise<{ client?: string | string[]; dir?: string | string[]; page?: string | string[]; search?: string | string[]; site?: string | string[]; sort?: string | string[]; status?: string | string[] }>;
};

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
  const selectedClientId = typeof query.client === "string" ? query.client : undefined;
  const selectedSiteId = typeof query.site === "string" ? query.site : undefined;
  const endpointStatus = query.status === "online" || query.status === "offline" || query.status === "pending" ? query.status : undefined;
  const endpointSort = query.sort === "hostname" || query.sort === "status" || query.sort === "last_seen" ? query.sort : "last_seen";
  const endpointDirection = query.dir === "asc" ? "asc" : "desc";
  const endpointPage = typeof query.page === "string" && /^\d+$/.test(query.page) ? Math.max(1, Number(query.page)) : 1;
  const endpointSearch = typeof query.search === "string" ? query.search.slice(0, 100) : undefined;

  let navigation: NavigationData | null = null;
  let endpointList: EndpointListData | null = null;
  let alerts: MonitoringAlert[] = [];
  let auditEvents: AuditEventRecord[] = [];
  let chainVerification: AuditChainVerification | null = null;
  let anchors: AuditAnchorRecord[] = [];
  let signingKeys: SigningKeyInfo | null = null;

  let navigationError = false;
  let endpointError = false;
  let alertsError = false;
  let auditError = false;
  let trustError = false;

  try {
    navigation = await getClientNavigation(session.sessionToken);
  } catch {
    navigationError = true;
  }

  try {
    endpointList = await getEndpointList(session.sessionToken, { clientId: selectedClientId, direction: endpointDirection, page: endpointPage, search: endpointSearch, siteId: selectedSiteId, sort: endpointSort, status: endpointStatus });
  } catch {
    endpointError = true;
  }

  try {
    alerts = await getMonitoringAlerts(session.sessionToken);
  } catch {
    alertsError = true;
  }

  try {
    const auditPage = await getAuditEventPage(session.sessionToken, { page: 1 });
    auditEvents = auditPage.items;
  } catch {
    auditError = true;
  }

  try {
    const [chain, anchorList, keys] = await Promise.all([
      verifyAuditChain(session.sessionToken).catch(() => null),
      getAuditAnchors(session.sessionToken).catch(() => []),
      getSigningKeys(session.sessionToken).catch(() => null),
    ]);
    chainVerification = chain;
    anchors = anchorList;
    signingKeys = keys;
  } catch {
    trustError = true;
  }

  const selectedSite = navigation?.items
    .flatMap((client) => client.sites)
    .find((site) => site.id === selectedSiteId);
  const selectedClient = navigation?.items.find((client) => client.id === selectedClientId);
  const validSelection = !selectedClientId && !selectedSiteId
    ? true
    : Boolean(selectedClient && selectedSite && selectedSite.client_id === selectedClient.id);

  return (
    <DashboardShell
      navigation={navigation}
      navigationError={navigationError}
      endpointError={endpointError}
      endpointList={endpointList}
      endpointSearch={endpointSearch ?? ""}
      endpointSort={endpointSort}
      endpointStatus={endpointStatus}
      alerts={alerts}
      alertsError={alertsError}
      auditEvents={auditEvents}
      auditError={auditError}
      chainVerification={chainVerification}
      anchors={anchors}
      signingKeys={signingKeys}
      trustError={trustError}
      operator={session.operator}
      selectedClientId={selectedClientId}
      selectedSiteId={selectedSiteId}
      selectionError={!validSelection}
    />
  );
}
