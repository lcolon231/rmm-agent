// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";

import { MonitoringPoliciesView, type PolicyRow } from "@/components/monitoring/policies-view";
import { getDashboardSession } from "@/lib/dashboard-session";
import type { MonitoringAlert, MonitoringPolicy } from "@/lib/monitoring-core";
import { getMonitoringAlerts, getMonitoringPolicies } from "@/lib/monitoring";
import { countAlertsByPolicy, parsePolicyFilter, policyRiskTone, sortPoliciesByRisk } from "@/lib/monitoring-view-core";

export const dynamic = "force-dynamic";

type MonitoringPageProps = {
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
};

export default async function MonitoringPoliciesPage({ searchParams }: MonitoringPageProps) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  const filter = parsePolicyFilter((await searchParams)?.state);
  let policies: MonitoringPolicy[] | null = null;
  let alerts: MonitoringAlert[] | null = null;
  const [policyResult, alertResult] = await Promise.allSettled([
    getMonitoringPolicies(session.sessionToken), getMonitoringAlerts(session.sessionToken),
  ]);
  if (policyResult.status === "fulfilled") policies = policyResult.value;
  if (alertResult.status === "fulfilled") alerts = alertResult.value;

  const alertsKnown = alerts !== null;
  const counts = countAlertsByPolicy(alerts ?? []);
  const visible = policies?.filter((policy) => filter === "all" || (filter === "active" ? policy.enabled : !policy.enabled)) ?? null;
  const rows: PolicyRow[] | null = visible
    ? sortPoliciesByRisk(visible, counts, alertsKnown).map((policy) => ({
        policy,
        alerts: alertsKnown ? (counts.get(policy.id) ?? { open: 0, critical: 0 }) : null,
        tone: policyRiskTone(policy, counts.get(policy.id), alertsKnown),
      }))
    : null;

  return (
    <MonitoringPoliciesView
      filter={filter}
      rows={rows}
      totals={
        policies
          ? {
              all: policies.length,
              active: policies.filter((policy) => policy.enabled).length,
              disabled: policies.filter((policy) => !policy.enabled).length,
              checks: policies.reduce((sum, policy) => sum + policy.check_count, 0),
            }
          : null
      }
      openAlerts={alerts ? alerts.filter((alert) => alert.state !== "resolved").length : null}
    />
  );
}
