// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";

import { MonitoringTabs } from "@/components/monitoring/monitoring-tabs";
import { PageHeader, PageStack } from "@/components/shell/page-header";
import { ErrorState } from "@/components/ui/states";
import { WebhookEndpointManager } from "@/components/webhook-endpoint-manager";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getWebhookEndpoints, getWebhookStatus } from "@/lib/monitoring";

export const dynamic = "force-dynamic";

export default async function WebhookDestinationsPage() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");
  const [endpointResult, statusResult] = await Promise.allSettled([
    getWebhookEndpoints(session.sessionToken),
    getWebhookStatus(session.sessionToken),
  ]);
  if (endpointResult.status === "rejected" || statusResult.status === "rejected") {
    return (
      <PageStack>
        <PageHeader
          breadcrumb={[{ label: "Devices" }, { label: "Monitoring", href: "/monitoring" }, { label: "Webhook destinations" }]}
          title="Webhook destinations"
          description="Other systems NodeLink tells when an alert changes."
        />
        <MonitoringTabs current="webhooks" />
        <section aria-label="Webhook destinations" className="rounded-[10px] border border-(--line) bg-(--paper)">
          <ErrorState
            title="Webhook settings could not be loaded"
            body="No destinations are shown because the server response could not be verified. Refresh once the management service is reachable"
          />
        </section>
      </PageStack>
    );
  }

  return (
    <WebhookEndpointManager
      initialEndpoints={endpointResult.value}
      status={statusResult.value}
      canAdmin={session.operator.role === "admin"}
      canOperate={session.operator.role !== "readonly"}
    />
  );
}
