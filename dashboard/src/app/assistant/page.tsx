// SPDX-License-Identifier: AGPL-3.0-only
import { redirect } from "next/navigation";
import { DashboardSectionShell } from "@/components/dashboard-shell";
import { AssistantChat } from "@/components/assistant/assistant-chat";
import { getAssistantContext } from "@/lib/assistant-context";
import { assistantPrefill } from "@/lib/assistant-context-core";
import { getDashboardSession } from "@/lib/dashboard-session";

export const dynamic = "force-dynamic";

export default async function AssistantPage({ searchParams }: {
  searchParams: Promise<{ client_id?: string; endpoint_id?: string }>;
}) {
  const session = await getDashboardSession();
  if (session.kind === "anonymous") redirect("/login");
  if (session.kind === "unavailable") return <main className="enrollment-standalone-error"><h1>Assistant unavailable</h1><p>Your session could not be verified.</p></main>;
  const { clients, state } = await getAssistantContext(session.sessionToken);
  const params = await searchParams;
  // The route segment is not an endpoint here, so only the query string counts.
  const { clientId, endpointId } = assistantPrefill("/assistant", {
    client_id: typeof params.client_id === "string" ? params.client_id : undefined,
    endpoint_id: typeof params.endpoint_id === "string" ? params.endpoint_id : undefined,
  }, clients?.items.map(client => client.id) ?? []);
  // No `assistant` prop: the full page is the assistant, so the floating widget stays off it.
  return <DashboardSectionShell activePath="/assistant" navigation={clients} navigationError={!clients}
    operator={session.operator}>
    <AssistantChat clients={clients?.items.map(({ id, name }) => ({ id, name })) ?? []}
      initialClientId={clientId} endpointId={clientId ? endpointId : undefined} state={state} />
  </DashboardSectionShell>;
}
