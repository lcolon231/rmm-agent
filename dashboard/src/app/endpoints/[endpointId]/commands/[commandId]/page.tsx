// SPDX-License-Identifier: AGPL-3.0-only

import { CommandDetailView } from "@/components/command-detail-view";
import { getCommandDetail } from "@/lib/command-console";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getEndpointDetail } from "@/lib/endpoint-detail";
import { NodelinkApiError } from "@/lib/nodelink-api";
import { PageFailure } from "@/components/endpoint/section-header";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";

export const dynamic = "force-dynamic";

export default async function CommandDetailPage({
  params,
  searchParams,
}: {
  params: Promise<{ endpointId: string; commandId: string }>;
  searchParams?: Promise<{ tab?: string | string[] }>;
}) {
  const session = await getDashboardSession();
  if (session.kind === "anonymous") redirect("/login");
  if (session.kind === "unavailable") {
    return (
      <PageFailure eyebrow="Session verification" title="The command record is temporarily unavailable" body="NodeLink could not verify your operator session. No command data was exposed.">
        <Link href="/">Return to Overview</Link>
      </PageFailure>
    );
  }

  const { endpointId, commandId } = await params;
  const query = (await searchParams) ?? {};
  const tab = query.tab === "custody" || query.tab === "details" ? query.tab : "output";

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
      <PageFailure eyebrow="Command record" title="This command could not be loaded" body="The server did not return the command record. Nothing was changed. Try again without changing the address.">
        <Link href={`/endpoints/${encodeURIComponent(endpointId)}/commands/${encodeURIComponent(commandId)}`}>Try again</Link>
        <Link href={`/endpoints/${encodeURIComponent(endpointId)}/commands`}>Back to commands</Link>
      </PageFailure>
    );
  }

  return <CommandDetailView command={command} endpoint={endpoint} operator={session.operator} tab={tab} />;
}
