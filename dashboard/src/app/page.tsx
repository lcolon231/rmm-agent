// SPDX-License-Identifier: AGPL-3.0-only

import { DashboardShell } from "@/components/dashboard-shell";
import { getClientNavigation, type NavigationData } from "@/lib/client-navigation";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getEndpointList, type EndpointListData } from "@/lib/endpoint-list";
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
  let navigationError = false;

  try {
    navigation = await getClientNavigation(session.sessionToken);
    endpointList = await getEndpointList(session.sessionToken, { clientId: selectedClientId, direction: endpointDirection, page: endpointPage, search: endpointSearch, siteId: selectedSiteId, sort: endpointSort, status: endpointStatus });
  } catch {
    navigationError = true;
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
      endpointList={endpointList}
      operator={session.operator}
      selectedClientId={selectedClientId}
      selectedSiteId={selectedSiteId}
      selectionError={!validSelection}
    />
  );
}
