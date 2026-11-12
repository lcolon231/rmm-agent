// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";

import { PatchPolicyManager } from "@/components/patch-policy-manager";
import { PATCH_POLICIES_DESCRIPTION } from "@/components/patching/copy";
import { PageHeader, PageStack } from "@/components/shell/page-header";
import { cardClass } from "@/components/ui/stat-tile";
import { ErrorState } from "@/components/ui/states";
import { getDashboardSession } from "@/lib/dashboard-session";
import { type PatchApprovalPolicy } from "@/lib/patch-policies-core";
import { getPatchPolicies } from "@/lib/patch-policies";

export const dynamic = "force-dynamic";

export default async function PatchPoliciesPage() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  let policies: PatchApprovalPolicy[] | null = null;
  const result = await Promise.allSettled([getPatchPolicies(session.sessionToken)]);
  if (result[0].status === "fulfilled") policies = result[0].value;

  if (policies === null) {
    return (
      <PageStack>
        <PageHeader breadcrumb={[{ label: "Patching" }, { label: "Patch policies" }]} title="Patch policies" description={PATCH_POLICIES_DESCRIPTION} />
        <div className={cardClass}>
          <ErrorState title="Patch policies could not be loaded" body="No policies are shown because the server response could not be verified" />
        </div>
      </PageStack>
    );
  }

  return <PatchPolicyManager initialPolicies={policies} canAdmin={session.operator.role === "admin"} />;
}
