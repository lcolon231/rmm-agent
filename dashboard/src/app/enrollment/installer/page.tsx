// SPDX-License-Identifier: AGPL-3.0-only

import Link from "next/link";
import { redirect } from "next/navigation";

import { InstallerDownloadForm } from "@/components/enrollment/installer-download-form";
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
    <>
      <header className="enrollment-page-head compact">
        <div>
          <span>Zero-touch deployment</span>
          <h1>Download agent installer</h1>
          <p>
            Package the agent for a site with a short-lived, single-use enrollment token
            built in. The person running it never types a server address or token.
          </p>
        </div>
      </header>
      {sites.length === 0 ? (
        <section className="enrollment-empty">
          <h2>A site is required</h2>
          <p>Create a client and site in NodeLink before downloading an installer.</p>
          <Link className="enrollment-primary-link" href="/enrollment/setup">
            Create client and site
          </Link>
        </section>
      ) : (
        <InstallerDownloadForm initialSiteId={initialSiteId} sites={sites} />
      )}
    </>
  );
}
