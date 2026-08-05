// SPDX-License-Identifier: AGPL-3.0-only

import { ArrowLeft, RadioTower, Webhook } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";

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
      <>
        <Link className="detail-back" href="/monitoring"><ArrowLeft size={15} /> Monitoring</Link>
        <header className="enrollment-page-head">
          <div><span>Notification transport</span><h1>Webhook destinations</h1><p>Signed destination data could not be verified, so no configuration is shown.</p></div>
        </header>
        <div className="enrollment-empty" role="alert"><RadioTower size={26} /><h3>Webhook configuration is unavailable</h3><p>Refresh after the management service is reachable.</p></div>
      </>
    );
  }

  return (
    <>
      <Link className="detail-back" href="/monitoring"><ArrowLeft size={15} /> Monitoring</Link>
      <header className="enrollment-page-head webhook-page-head">
        <div>
          <span>Notification transport</span>
          <h1>Webhook destinations</h1>
          <p>Deliver alert transitions to external systems with stable event IDs, encrypted rotating secrets, pinned public addresses, and an operator-visible retry ledger.</p>
        </div>
        <span className="webhook-version-mark"><Webhook size={15} /> Contract v1</span>
      </header>
      <WebhookEndpointManager
        initialEndpoints={endpointResult.value}
        status={statusResult.value}
        canAdmin={session.operator.role === "admin"}
        canOperate={session.operator.role !== "readonly"}
      />
    </>
  );
}
