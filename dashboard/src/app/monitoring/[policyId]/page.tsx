// SPDX-License-Identifier: AGPL-3.0-only

import { notFound, redirect } from "next/navigation";

import { NotFoundPanel } from "@/components/monitoring/not-found-panel";
import { PolicyDetailView } from "@/components/monitoring/policy-detail-view";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getMonitoringPolicy } from "@/lib/monitoring";
import { parsePolicyTab } from "@/lib/monitoring-view-core";
import { NodelinkApiError } from "@/lib/nodelink-api";

export const dynamic = "force-dynamic";

export default async function MonitoringPolicyPage({
  params,
  searchParams,
}: {
  params: Promise<{ policyId: string }>;
  searchParams?: Promise<{ tab?: string | string[] }>;
}) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");
  const { policyId } = await params;
  const tab = parsePolicyTab((await searchParams)?.tab);

  let policy;
  try {
    policy = await getMonitoringPolicy(session.sessionToken, policyId);
  } catch (error) {
    if (error instanceof NodelinkApiError && error.status === 404) notFound();
    return (
      <NotFoundPanel
        role="alert"
        title="Monitoring policy is unavailable"
        body="No checks are shown because the policy response could not be verified. Nothing was changed."
        href="/monitoring"
        linkLabel="Back to monitoring policies"
      />
    );
  }

  return <PolicyDetailView policy={policy} tab={tab} />;
}
