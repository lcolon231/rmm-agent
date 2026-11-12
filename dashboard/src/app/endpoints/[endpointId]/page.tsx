// SPDX-License-Identifier: AGPL-3.0-only

import Link from "next/link";
import { notFound, redirect } from "next/navigation";

import { EndpointDetailView } from "@/components/endpoint-detail-view";
import { getCommandHistory } from "@/lib/command-console";
import { getDashboardSession } from "@/lib/dashboard-session";
import { deviceStatus, indexOpenAlerts } from "@/lib/device-status-core";
import { getEndpointDetail } from "@/lib/endpoint-detail";
import { detailAsListItem } from "@/lib/endpoint-summary-core";
import { getMonitoringAlerts } from "@/lib/monitoring";
import { NodelinkApiError } from "@/lib/nodelink-api";

export const dynamic = "force-dynamic";

const RECENT_COMMANDS = 5;

/** Rendered inside the app shell, so it is a section, not a second <main>. */
function Failure({ eyebrow, title, body, children }: { eyebrow: string; title: string; body: string; children?: React.ReactNode }) {
  return (
    <section role="alert" className="grid max-w-[640px] gap-2 rounded-[10px] border border-(--line) bg-(--paper) p-6">
      <span className="text-xs text-(--muted)">{eyebrow}</span>
      <h1 className="m-0 text-2xl font-semibold text-(--ink)">{title}</h1>
      <p className="m-0 text-sm text-(--slate)">{body}</p>
      <p className="m-0 mt-2 flex flex-wrap gap-4 text-sm font-semibold">{children}</p>
    </section>
  );
}

export default async function EndpointPage({
  params,
  searchParams,
}: {
  params: Promise<{ endpointId: string }>;
  searchParams: Promise<{ hours?: string | string[]; tab?: string | string[] }>;
}) {
  const session = await getDashboardSession();
  if (session.kind === "anonymous") redirect("/login");
  if (session.kind === "unavailable") {
    return (
      <Failure eyebrow="Session verification" title="Endpoint details are temporarily unavailable" body="NodeLink could not verify your operator session. No endpoint data was exposed.">
        <Link href="/">Return to Overview</Link>
      </Failure>
    );
  }

  const { endpointId } = await params;
  const query = await searchParams;
  const requestedHours = typeof query.hours === "string" ? Number(query.hours) : 24;
  const historyHours = [6, 24, 72, 168].includes(requestedHours) ? requestedHours : 24;
  const tab = query.tab === "remote" ? "remote" : "summary";

  const [detail, alerts, commands] = await Promise.allSettled([
    getEndpointDetail(session.sessionToken, endpointId, { historyHours, historyLimit: 500 }),
    getMonitoringAlerts(session.sessionToken),
    getCommandHistory(session.sessionToken, endpointId, { pageSize: RECENT_COMMANDS }),
  ]);

  if (detail.status === "rejected") {
    if (detail.reason instanceof NodelinkApiError && detail.reason.status === 404) notFound();
  }
  const endpoint = detail.status === "fulfilled" ? detail.value : null;
  if (endpoint === null) {
    return (
      <Failure eyebrow="Device" title="Telemetry could not be loaded" body="The server did not return this device's details. Nothing was changed. Try again without changing the device.">
        <Link href={`/endpoints/${encodeURIComponent(endpointId)}?hours=${historyHours}`}>Try again</Link>
        <Link href="/endpoints">Back to Endpoints</Link>
      </Failure>
    );
  }

  const now = new Date();
  // Without alerts nothing is called critical; the status falls back to what the device reports.
  const status = deviceStatus(detailAsListItem(endpoint), indexOpenAlerts(alerts.status === "fulfilled" ? alerts.value : []), now);

  return (
    <EndpointDetailView
      endpoint={endpoint}
      operator={session.operator}
      status={status}
      commands={commands.status === "fulfilled" ? commands.value.items.slice(0, RECENT_COMMANDS) : null}
      tab={tab}
      now={now.toISOString()}
    />
  );
}
