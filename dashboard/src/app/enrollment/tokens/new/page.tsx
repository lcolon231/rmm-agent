// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";
import Link from "next/link";

import { CreateTokenForm } from "@/components/enrollment/create-token-form";
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
    <>
      <header className="enrollment-page-head compact"><div><span>New temporary credential</span><h1>Create enrollment token</h1><p>Constrain who, where, and how many agents may enroll before this credential expires.</p></div></header>
      {sites.length === 0 ? (
        <section className="enrollment-empty">
          <h2>A site is required</h2>
          <p>Create a client and site in NodeLink before issuing an enrollment token.</p>
          <Link className="enrollment-primary-link" href="/enrollment/setup">
            Create client and site
          </Link>
        </section>
      ) : <CreateTokenForm initialSiteId={initialSiteId} sites={sites} />}
    </>
  );
}
