// SPDX-License-Identifier: AGPL-3.0-only

import { ManagedSurface } from "@/components/admin/managed-surface";
import { PageHeader } from "@/components/shell/page-header";
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
    <ManagedSurface>
<PageHeader breadcrumb={[{ label: "Administration" }, { label: "Client setup" }]} title={"Client setup"} description="Create the client and site needed before issuing an enrollment token." />
      <ClientSiteSetup initialClients={navigation.items} />
    </ManagedSurface>
  );
}
