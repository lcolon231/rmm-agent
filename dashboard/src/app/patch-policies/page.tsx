// SPDX-License-Identifier: AGPL-3.0-only

import { Layers3 } from "lucide-react";
import { redirect } from "next/navigation";

import { PatchPolicyManager } from "@/components/patch-policy-manager";
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

  return (
    <>
      <header className="enrollment-page-head">
        <div>
          <span>Versioned configuration</span>
          <h1>Patch approval policies</h1>
          <p>
            Windows Update approval rules across global, client, site, and endpoint scopes.
            Installs are gated server-side against the most specific policy.
          </p>
        </div>
        <span className="monitoring-readonly-note">{session.operator.role === "admin" ? "Administrator" : "Read-only"}</span>
      </header>

      <section className="setup-boundary-banner">
        <Layers3 aria-hidden="true" size={22} />
        <div>
          <strong>Most-specific policy wins</strong>
          <span>
            The single most specific policy that targets an endpoint governs its installs. Unmatched
            updates fall to the policy default. With no policy, installs proceed unchanged.
          </span>
        </div>
      </section>

      {policies === null ? (
        <div className="enrollment-empty" role="alert">
          <h3>Patch approval policies could not be loaded</h3>
          <p>No policies are shown because the server response could not be verified.</p>
        </div>
      ) : (
        <PatchPolicyManager initialPolicies={policies} canAdmin={session.operator.role === "admin"} />
      )}
    </>
  );
}
