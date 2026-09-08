// SPDX-License-Identifier: AGPL-3.0-only
import { redirect } from "next/navigation";
import { DashboardSectionShell } from "@/components/dashboard-shell";
import { AssistantChat } from "@/components/assistant/assistant-chat";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getClientNavigation } from "@/lib/client-navigation";
import { assistantRequest } from "@/lib/nodelink-assistant";

export const dynamic = "force-dynamic";

export default async function AssistantPage({ searchParams }: {
  searchParams: Promise<{ client_id?: string; endpoint_id?: string }>;
}) {
  const session = await getDashboardSession();
  if (session.kind === "anonymous") redirect("/login");
  if (session.kind === "unavailable") return <main className="enrollment-standalone-error"><h1>Assistant unavailable</h1><p>Your session could not be verified.</p></main>;
  const [navigation, status] = await Promise.allSettled([
    getClientNavigation(session.sessionToken), assistantRequest("/api/v1/assistant/status", session.sessionToken),
  ]);
  const clients = navigation.status === "fulfilled" ? navigation.value : null;
  const state = status.status === "fulfilled" && status.value && typeof status.value === "object" && "state" in status.value ? String(status.value.state) : "unavailable";
  const params = await searchParams;
  const clientId = clients?.items.some(client => client.id === params.client_id) ? params.client_id : undefined;
  const endpointId = typeof params.endpoint_id === "string" && /^[a-f0-9-]{36}$/i.test(params.endpoint_id) ? params.endpoint_id : undefined;
  return <DashboardSectionShell activePath="/assistant" navigation={clients} navigationError={!clients}
    operator={session.operator} sectionLabel="Read-only investigation" sectionTitle="AI assistant">
    <AssistantChat clients={clients?.items.map(({ id, name }) => ({ id, name })) ?? []}
      initialClientId={clientId} endpointId={clientId ? endpointId : undefined} state={state} />
  </DashboardSectionShell>;
}
