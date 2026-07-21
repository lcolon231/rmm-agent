// SPDX-License-Identifier: AGPL-3.0-only

import { EndpointDetailView } from "@/components/endpoint-detail-view";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getEndpointDetail } from "@/lib/endpoint-detail";
import { NodelinkApiError } from "@/lib/nodelink-api";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";

export const dynamic = "force-dynamic";

export default async function EndpointPage({
  params,
  searchParams,
}: {
  params: Promise<{ endpointId: string }>;
  searchParams: Promise<{ hours?: string | string[] }>;
}) {
  const session = await getDashboardSession();
  if (session.kind === "anonymous") redirect("/login");
  if (session.kind === "unavailable") {
    return (
      <main className="detail-failure-page">
        <section role="alert"><span>Session verification</span><h1>Endpoint details are temporarily unavailable</h1><p>NodeLink could not verify your operator session. No endpoint data was exposed.</p><Link href="/">Return to fleet</Link></section>
      </main>
    );
  }

  const { endpointId } = await params;
  const query = await searchParams;
  const requestedHours = typeof query.hours === "string" ? Number(query.hours) : 24;
  const historyHours = [6, 24, 72, 168].includes(requestedHours) ? requestedHours : 24;

  let endpoint = null;
  let loadFailed = false;
  try {
    endpoint = await getEndpointDetail(session.sessionToken, endpointId, { historyHours, historyLimit: 500 });
  } catch (error) {
    if (error instanceof NodelinkApiError && error.status === 404) notFound();
    loadFailed = true;
  }

  if (loadFailed || endpoint === null) {
    return (
      <main className="detail-failure-page">
        <section role="alert"><span>Endpoint diagnostics</span><h1>Telemetry could not be loaded</h1><p>The server did not return endpoint details. Try again without changing the endpoint.</p><Link href={`/endpoints/${encodeURIComponent(endpointId)}?hours=${historyHours}`}>Try again</Link><Link href="/">Return to fleet</Link></section>
      </main>
    );
  }

  return <EndpointDetailView endpoint={endpoint} operator={session.operator} />;
}
