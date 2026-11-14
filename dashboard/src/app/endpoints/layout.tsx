// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";

import { DashboardSectionShell } from "@/components/dashboard-shell";
import { getAssistantContext } from "@/lib/assistant-context";
import { getDashboardSession } from "@/lib/dashboard-session";

export const dynamic = "force-dynamic";

export default async function EndpointsLayout({ children }: { children: React.ReactNode }) {
  const session = await getDashboardSession();
  if (session.kind === "anonymous") redirect("/login");
  if (session.kind === "unavailable") {
    return (
      <main className="enrollment-standalone-error">
        <h1>Endpoints operations are unavailable</h1>
        <p>Your session could not be verified. No endpoint inventory data was loaded.</p>
      </main>
    );
  }

  const assistant = await getAssistantContext(session.sessionToken);

  return (
    <DashboardSectionShell
      activePath="/endpoints"
      navigation={assistant.clients}
      navigationError={!assistant.clients}
      assistantState={assistant.state}
      operator={session.operator}
    >
      {children}
    </DashboardSectionShell>
  );
}
