// SPDX-License-Identifier: AGPL-3.0-only

import { Layers3, ShieldCheck } from "lucide-react";
import { redirect } from "next/navigation";

import { getDashboardSession } from "@/lib/dashboard-session";
import { formatMonitoringTimestamp } from "@/lib/monitoring-core";
import { formatPatchScope, type PatchApprovalPolicy } from "@/lib/patch-policies-core";
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
            Read-only inventory of Windows Update approval rules across global, client, site, and
            endpoint scopes. Installs are gated server-side against the most specific policy.
          </p>
        </div>
        <span className="monitoring-readonly-note">Read-only foundation</span>
      </header>

      <section className="setup-boundary-banner">
        <Layers3 aria-hidden="true" size={22} />
        <div>
          <strong>Most-specific policy wins</strong>
          <span>
            The single most specific policy that targets an endpoint governs its installs. Ordered
            rules approve, deny, or defer updates by classification, severity, or KB; unmatched
            updates fall to the policy default. With no policy, installs proceed unchanged.
          </span>
        </div>
      </section>

      <section className="enrollment-panel">
        <header>
          <div>
            <span>Policy register</span>
            <h2>{policies === null ? "Unavailable" : `${policies.length} policies`}</h2>
            <small>Current revisions only; each edit appends an auditable version.</small>
          </div>
          <ShieldCheck aria-hidden="true" size={19} />
        </header>

        {policies === null ? (
          <div className="enrollment-empty" role="alert">
            <ShieldCheck size={24} />
            <h3>Patch approval policies could not be loaded</h3>
            <p>No policies are shown because the server response could not be verified.</p>
          </div>
        ) : policies.length === 0 ? (
          <div className="enrollment-empty">
            <ShieldCheck size={24} />
            <h3>No patch approval policies yet</h3>
            <p>Until a policy is created, Windows Update installs proceed without an approval gate.</p>
          </div>
        ) : (
          <div className="enrollment-table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Policy</th>
                  <th>Scope</th>
                  <th>Status</th>
                  <th>Rules</th>
                  <th>Default</th>
                  <th>Window</th>
                  <th>Reboot</th>
                  <th>Revision</th>
                  <th>Created (UTC)</th>
                </tr>
              </thead>
              <tbody>
                {policies.map((policy) => (
                  <tr key={policy.id}>
                    <td><strong>{policy.name}</strong><code>{policy.id}</code></td>
                    <td>
                      <strong>{formatPatchScope(policy.scope)}</strong>
                      <code>{policy.scope_id ?? "All managed endpoints"}</code>
                    </td>
                    <td>
                      <span className={`monitoring-status ${policy.enabled ? "enabled" : "disabled"}`}>
                        {policy.enabled ? "Enabled" : "Disabled"}
                      </span>
                    </td>
                    <td>{policy.rule_count}</td>
                    <td>{policy.default_action === "approve" ? "Approve" : "Deny"}</td>
                    <td>{policy.require_maintenance_window ? "Required" : "—"}</td>
                    <td>{policy.reboot_policy === "never" ? "—" : policy.reboot_policy.replaceAll("_", " ")}</td>
                    <td><code>v{policy.current_version}</code></td>
                    <td>{formatMonitoringTimestamp(policy.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
