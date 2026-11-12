// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";

import { PatchComplianceView } from "@/components/patching/patch-compliance-view";
import { getDashboardSession } from "@/lib/dashboard-session";
import {
  type ComplianceListData,
  type ComplianceSummary,
} from "@/lib/patch-compliance-core";
import { getComplianceList, getComplianceSummary } from "@/lib/patch-compliance";
import { parseComplianceState, sortComplianceRows, type ComplianceQuery } from "@/lib/patch-compliance-view-core";

export const dynamic = "force-dynamic";

const PAGE_SIZE = 25;

type SearchParams = {
  client_id?: string;
  page?: string;
  search?: string;
  site_id?: string;
  state?: string;
};

export default async function PatchCompliancePage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  const raw = await searchParams;
  const requestedPage = typeof raw.page === "string" ? Number(raw.page) : 1;
  const page = Number.isInteger(requestedPage) && requestedPage >= 1 ? requestedPage : 1;
  const clientId = raw.client_id?.trim() || undefined;
  const siteId = raw.site_id?.trim() || undefined;
  const state = parseComplianceState(raw.state);
  const search = raw.search?.trim() || undefined;
  const scope = { clientId, siteId };

  let summary: ComplianceSummary | null = null;
  let report: ComplianceListData | null = null;
  const [summaryResult, reportResult] = await Promise.allSettled([
    getComplianceSummary(session.sessionToken, scope),
    getComplianceList(session.sessionToken, {
      ...scope,
      state,
      search,
      page,
      pageSize: PAGE_SIZE,
    }),
  ]);
  if (summaryResult.status === "fulfilled") summary = summaryResult.value;
  // The server orders by hostname; the most urgent rows go first within this page.
  if (reportResult.status === "fulfilled") {
    report = { ...reportResult.value, items: sortComplianceRows(reportResult.value.items) };
  }

  const query: ComplianceQuery = { clientId, siteId, state, search, page };

  return (
    <PatchComplianceView
      query={query}
      summary={summary}
      report={report}
      pageSize={PAGE_SIZE}
      now={new Date().toISOString()}
    />
  );
}
