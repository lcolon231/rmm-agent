// SPDX-License-Identifier: AGPL-3.0-only

import Link from "next/link";
import { notFound, redirect } from "next/navigation";

import { RetentionPolicyPanel } from "@/components/retention-policy-panel";
import { PageHeader, PageStack } from "@/components/shell/page-header";
import { getClientNavigationEntry } from "@/lib/client-navigation";
import { getDashboardSession } from "@/lib/dashboard-session";
import { NodelinkApiError } from "@/lib/nodelink-api";
import { getRetentionPolicy } from "@/lib/retention-policy";

export const dynamic = "force-dynamic";

export default async function ClientPage({ params }: { params: Promise<{ clientId: string }> }) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");
  const { clientId } = await params;

  const [client, policy] = await Promise.allSettled([
    getClientNavigationEntry(session.sessionToken, clientId),
    getRetentionPolicy(session.sessionToken, clientId),
  ]);
  // A client the operator cannot see answers 404 exactly like a missing one.
  for (const result of [client, policy]) {
    if (result.status === "rejected" && result.reason instanceof NodelinkApiError && result.reason.status === 404) {
      notFound();
    }
  }
  const name = client.status === "fulfilled" ? client.value.name : "Client";

  return (
    <PageStack>
      <PageHeader
        breadcrumb={[{ label: name, href: `/?client=${encodeURIComponent(clientId)}` }, { label: "Client details" }]}
        title={name}
        description="Settings that apply to this client's data."
      />
      {policy.status === "fulfilled" && policy.value ? (
        <RetentionPolicyPanel clientId={clientId} initialPolicy={policy.value} />
      ) : (
        <section role="alert" className="grid max-w-[640px] gap-2 rounded-[10px] border border-(--line) bg-(--paper) p-6">
          <h2 className="m-0 text-lg font-semibold text-(--ink)">The retention policy could not be loaded</h2>
          <p className="m-0 text-sm text-(--slate)">Nothing was changed. Try again in a moment.</p>
          <p className="m-0 text-sm font-semibold"><Link href={`/clients/${encodeURIComponent(clientId)}`}>Retry</Link></p>
        </section>
      )}
    </PageStack>
  );
}
