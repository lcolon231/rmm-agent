// SPDX-License-Identifier: AGPL-3.0-only

import { LockKeyhole } from "lucide-react";
import { redirect } from "next/navigation";

import { DashboardSectionShell } from "@/components/dashboard-shell";
import { getClientNavigation, type NavigationData } from "@/lib/client-navigation";
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

  let navigation: NavigationData | null = null;
  let navigationError = false;
  try {
    navigation = await getClientNavigation(session.sessionToken);
  } catch {
    navigationError = true;
  }

  return (
    <DashboardSectionShell
      activePath="/operators"
      navigation={navigation}
      navigationError={navigationError}
      operator={session.operator}
      sectionLabel="Administration"
      sectionTitle="Operator access control"
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
