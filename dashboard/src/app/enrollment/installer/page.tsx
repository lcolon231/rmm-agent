// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";

import { EnrollmentHeader } from "@/components/enrollment/enrollment-header";
import { InstallerDownloadForm } from "@/components/enrollment/installer-download-form";
import { SiteRequired } from "@/components/enrollment/site-required";
import { PageStack } from "@/components/shell/page-header";
import { getClientNavigation } from "@/lib/client-navigation";
import { getDashboardSession } from "@/lib/dashboard-session";

export default async function DownloadInstallerPage({
  searchParams,
}: {
  searchParams: Promise<{ site?: string | string[] }>;
}) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");
  if (session.operator.role === "readonly") redirect("/enrollment/tokens");

  const requestedSite = (await searchParams).site;
  const navigation = await getClientNavigation(session.sessionToken);
  const sites = navigation.items.flatMap((client) =>
    client.sites.map((site) => ({ id: site.id, label: `${client.name} / ${site.name}` })),
  );
  const initialSiteId =
    typeof requestedSite === "string" && sites.some((site) => site.id === requestedSite)
      ? requestedSite
      : undefined;

  return (
    <PageStack>
      <EnrollmentHeader
        tab="installer"
        role={session.operator.role}
        trail={[{ label: "Installer" }]}
        title="Download an installer"
        description="Package the agent for one site with a short-lived, single-use token built in. Whoever runs it never types a server address or token."
      />
      {sites.length === 0 ? (
        <SiteRequired body="Create a client and site in NodeLink before downloading an installer." />
      ) : (
        <InstallerDownloadForm initialSiteId={initialSiteId} sites={sites} />
      )}
    </PageStack>
  );
}
