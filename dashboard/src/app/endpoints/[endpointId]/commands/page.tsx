// SPDX-License-Identifier: AGPL-3.0-only

import { CommandConsoleView } from "@/components/command-console-view";
import { getCommandHistory } from "@/lib/command-console";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getEndpointDetail } from "@/lib/endpoint-detail";
import { getMaintenanceWindows } from "@/lib/maintenance-windows";
import type { MaintenanceWindow } from "@/lib/maintenance-windows-core";
import { NodelinkApiError } from "@/lib/nodelink-api";
import { PageFailure } from "@/components/endpoint/section-header";
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
      <PageFailure eyebrow="Session verification" title="The command console is temporarily unavailable" body="NodeLink could not verify your operator session. No command data was exposed.">
        <Link href="/">Return to Overview</Link>
      </PageFailure>
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
      <PageFailure eyebrow="Commands" title="Command history could not be loaded" body="The server did not return this device's command data. Nothing was changed. Try again without changing the device.">
        <Link href={`/endpoints/${encodeURIComponent(endpointId)}/commands`}>Try again</Link>
        <Link href={`/endpoints/${encodeURIComponent(endpointId)}`}>Back to the device</Link>
      </PageFailure>
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
