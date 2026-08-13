// SPDX-License-Identifier: AGPL-3.0-only

import { CommandConsoleView } from "@/components/command-console-view";
import { getCommandHistory } from "@/lib/command-console";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getEndpointDetail } from "@/lib/endpoint-detail";
import { getMaintenanceWindows } from "@/lib/maintenance-windows";
import type { MaintenanceWindow } from "@/lib/maintenance-windows-core";
import { NodelinkApiError } from "@/lib/nodelink-api";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";

export const dynamic = "force-dynamic";

export default async function EndpointCommandsPage({
  params,
  searchParams,
}: {
  params: Promise<{ endpointId: string }>;
  searchParams: Promise<{ page?: string | string[] }>;
}) {
  const session = await getDashboardSession();
  if (session.kind === "anonymous") redirect("/login");
  if (session.kind === "unavailable") {
    return (
      <main className="detail-failure-page">
        <section role="alert"><span>Session verification</span><h1>The command console is temporarily unavailable</h1><p>NodeLink could not verify your operator session. No command data was exposed.</p><Link href="/">Return to fleet</Link></section>
      </main>
    );
  }

  const { endpointId } = await params;
  const query = await searchParams;
  const requestedPage = typeof query.page === "string" ? Number(query.page) : 1;
  const page = Number.isInteger(requestedPage) && requestedPage >= 1 ? requestedPage : 1;

  let endpoint = null;
  let history = null;
  try {
    [endpoint, history] = await Promise.all([
      getEndpointDetail(session.sessionToken, endpointId, { historyHours: 6, historyLimit: 10 }),
      getCommandHistory(session.sessionToken, endpointId, { page }),
    ]);
  } catch (error) {
    if (error instanceof NodelinkApiError && error.status === 404) notFound();
  }

  if (endpoint === null || history === null) {
    return (
      <main className="detail-failure-page">
        <section role="alert"><span>Command console</span><h1>Command history could not be loaded</h1><p>The server did not return this endpoint&apos;s command data. Try again without changing the endpoint.</p><Link href={`/endpoints/${encodeURIComponent(endpointId)}/commands`}>Try again</Link><Link href="/">Return to fleet</Link></section>
      </main>
    );
  }

  // Coverage is advisory here — the console must still load when the window
  // inventory does not, so a failure degrades to "unverified" rather than an error.
  let maintenanceWindows: MaintenanceWindow[] | null = null;
  const windowResult = await Promise.allSettled([getMaintenanceWindows(session.sessionToken)]);
  if (windowResult[0].status === "fulfilled") maintenanceWindows = windowResult[0].value;

  // Serialized into the client component as the hydration-stable "now" for
  // maintenance-window coverage; the browser takes over from there.
  // eslint-disable-next-line react-hooks/purity
  const renderedAt = Date.now();

  return (
    <CommandConsoleView
      endpoint={endpoint}
      history={history}
      maintenanceWindows={maintenanceWindows}
      operator={session.operator}
      serverNowMs={renderedAt}
    />
  );
}
