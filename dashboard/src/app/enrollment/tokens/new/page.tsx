// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";

import { CreateTokenForm } from "@/components/enrollment/create-token-form";
import { EnrollmentHeader } from "@/components/enrollment/enrollment-header";
import { SiteRequired } from "@/components/enrollment/site-required";
import { PageStack } from "@/components/shell/page-header";
import { getClientNavigation } from "@/lib/client-navigation";
import { getDashboardSession } from "@/lib/dashboard-session";

export default async function CreateEnrollmentTokenPage({
  searchParams,
}: {
  searchParams: Promise<{ site?: string | string[] }>;
}) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");
  if (session.operator.role === "readonly") redirect("/enrollment/tokens");
  const requestedSite = (await searchParams).site;
  const navigation = await getClientNavigation(session.sessionToken);
  const sites = navigation.items.flatMap((client) => client.sites.map((site) => ({ id: site.id, label: `${client.name} / ${site.name}` })));
  const initialSiteId = typeof requestedSite === "string"
    && sites.some((site) => site.id === requestedSite)
    ? requestedSite
    : undefined;
  return (
    <PageStack>
      <EnrollmentHeader
        tab="tokens"
        role={session.operator.role}
        trail={[{ label: "Tokens", href: "/enrollment/tokens" }, { label: "New token" }]}
        title="Create enrollment token"
        description="Limit where, how often and until when a new device may use this token to join."
      />
      {sites.length === 0 ? (
        <SiteRequired body="Create a client and site in NodeLink before issuing an enrollment token." />
      ) : <CreateTokenForm initialSiteId={initialSiteId} sites={sites} />}
    </PageStack>
  );
}
