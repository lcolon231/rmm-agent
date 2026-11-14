// SPDX-License-Identifier: AGPL-3.0-only

import { LockKeyhole } from "lucide-react";
import { redirect } from "next/navigation";

import { DashboardSectionShell } from "@/components/dashboard-shell";
import { getAssistantContext } from "@/lib/assistant-context";
import { getDashboardSession } from "@/lib/dashboard-session";

export const dynamic = "force-dynamic";

export default async function OperatorsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const session = await getDashboardSession();
  if (session.kind === "anonymous") redirect("/login");
  if (session.kind === "unavailable") {
    return (
      <main className="enrollment-standalone-error">
        <h1>Operator management is unavailable</h1>
        <p>Your session could not be verified. No protected operator data was loaded.</p>
      </main>
    );
  }

  const assistant = await getAssistantContext(session.sessionToken);

  return (
    <DashboardSectionShell
      activePath="/operators"
      navigation={assistant.clients}
      navigationError={!assistant.clients}
      assistantState={assistant.state}
      operator={session.operator}
    >
      {session.operator.role === "admin" ? children : (
        <section className="operator-access-denied" role="alert">
          <LockKeyhole aria-hidden="true" size={28} />
          <span>Administrator access required</span>
          <h1>Operator management is restricted</h1>
          <p>
            Your signed-in role cannot list or change operator identities. The NodeLink API enforces this boundary independently of the page.
          </p>
        </section>
      )}
    </DashboardSectionShell>
  );
}
