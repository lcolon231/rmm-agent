// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";

import { DashboardSectionShell } from "@/components/dashboard-shell";
import { getClientNavigation, type NavigationData } from "@/lib/client-navigation";
import { getDashboardSession } from "@/lib/dashboard-session";

export const dynamic = "force-dynamic";

export default async function AlertsLayout({ children }: { children: React.ReactNode }) {
  const session = await getDashboardSession();
  if (session.kind === "anonymous") redirect("/login");
  if (session.kind === "unavailable") {
    return (
      <main className="enrollment-standalone-error">
        <h1>Alerts are unavailable</h1>
        <p>Your session could not be verified. No protected alert data was loaded.</p>
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
      activePath="/alerts"
      navigation={navigation}
      navigationError={navigationError}
      operator={session.operator}
      sectionLabel="Operations"
      sectionTitle="Alerts"
    >
      {children}
    </DashboardSectionShell>
  );
}
