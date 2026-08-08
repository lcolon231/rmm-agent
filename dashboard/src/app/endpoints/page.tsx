// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";

import { EndpointsView } from "@/components/endpoints-view";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getEndpointList, type EndpointListData } from "@/lib/endpoint-list";

export const dynamic = "force-dynamic";

type EndpointsPageProps = {
  searchParams: Promise<{
    client?: string | string[];
    dir?: string | string[];
    page?: string | string[];
    search?: string | string[];
    site?: string | string[];
    sort?: string | string[];
    status?: string | string[];
  }>;
};

export default async function EndpointsPage({ searchParams }: EndpointsPageProps) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  const query = await searchParams;
  const selectedClientId = typeof query.client === "string" ? query.client : undefined;
  const selectedSiteId = typeof query.site === "string" ? query.site : undefined;
  const endpointStatus =
    query.status === "online" || query.status === "offline" || query.status === "pending"
      ? query.status
      : undefined;
  const endpointSort =
    query.sort === "hostname" || query.sort === "status" || query.sort === "last_seen"
      ? query.sort
      : "last_seen";
  const endpointDirection = query.dir === "asc" ? "asc" : "desc";
  const endpointPage =
    typeof query.page === "string" && /^\d+$/.test(query.page)
      ? Math.max(1, Number(query.page))
      : 1;
  const endpointSearch = typeof query.search === "string" ? query.search.slice(0, 100) : undefined;

  let endpointList: EndpointListData | null = null;
  let endpointError = false;

  try {
    endpointList = await getEndpointList(session.sessionToken, {
      clientId: selectedClientId,
      direction: endpointDirection,
      page: endpointPage,
      search: endpointSearch,
      siteId: selectedSiteId,
      sort: endpointSort,
      status: endpointStatus,
    });
  } catch {
    endpointError = true;
  }

  return (
    <EndpointsView
      endpointError={endpointError}
      endpointList={endpointList}
      endpointSearch={endpointSearch || ""}
      endpointSort={endpointSort}
      endpointStatus={endpointStatus}
    />
  );
}
