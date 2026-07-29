// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";

import { ClientSiteSetup } from "@/components/enrollment/client-site-setup";
import { getClientNavigation } from "@/lib/client-navigation";
import { getDashboardSession } from "@/lib/dashboard-session";

export default async function ClientSiteSetupPage() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");
  if (session.operator.role === "readonly") redirect("/enrollment");
  const navigation = await getClientNavigation(session.sessionToken);

  return (
    <>
      <header className="enrollment-page-head compact">
        <div>
          <span>Deployment onboarding</span>
          <h1>Clients and sites</h1>
          <p>
            Establish the customer and location boundary required before an
            enrollment token can be issued.
          </p>
        </div>
      </header>
      <ClientSiteSetup initialClients={navigation.items} />
    </>
  );
}
