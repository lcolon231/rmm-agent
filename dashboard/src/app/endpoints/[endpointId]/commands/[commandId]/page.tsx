// SPDX-License-Identifier: AGPL-3.0-only

import { CommandDetailView } from "@/components/command-detail-view";
import { getCommandDetail } from "@/lib/command-console";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getEndpointDetail } from "@/lib/endpoint-detail";
import { NodelinkApiError } from "@/lib/nodelink-api";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";

export const dynamic = "force-dynamic";

export default async function CommandDetailPage({
  params,
}: {
  params: Promise<{ endpointId: string; commandId: string }>;
}) {
  const session = await getDashboardSession();
  if (session.kind === "anonymous") redirect("/login");
  if (session.kind === "unavailable") {
    return (
      <main className="detail-failure-page">
        <section role="alert"><span>Session verification</span><h1>The command record is temporarily unavailable</h1><p>NodeLink could not verify your operator session. No command data was exposed.</p><Link href="/">Return to fleet</Link></section>
      </main>
    );
  }

  const { endpointId, commandId } = await params;

  let endpoint = null;
  let command = null;
  try {
    [endpoint, command] = await Promise.all([
      getEndpointDetail(session.sessionToken, endpointId, { historyHours: 6, historyLimit: 10 }),
      getCommandDetail(session.sessionToken, endpointId, commandId),
    ]);
  } catch (error) {
    if (error instanceof NodelinkApiError && error.status === 404) notFound();
  }

  if (endpoint === null || command === null) {
    return (
      <main className="detail-failure-page">
        <section role="alert"><span>Command record</span><h1>This command could not be loaded</h1><p>The server did not return the command record. Try again without changing the address.</p><Link href={`/endpoints/${encodeURIComponent(endpointId)}/commands`}>Back to command console</Link><Link href="/">Return to fleet</Link></section>
      </main>
    );
  }

  return <CommandDetailView command={command} endpoint={endpoint} operator={session.operator} />;
}
