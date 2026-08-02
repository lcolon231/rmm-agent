// SPDX-License-Identifier: AGPL-3.0-only

import { Activity, Layers3 } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";

import { getDashboardSession } from "@/lib/dashboard-session";
import {
  formatMonitoringScope,
  formatMonitoringTimestamp,
  type MonitoringPolicy,
} from "@/lib/monitoring-core";
import { getMonitoringPolicies } from "@/lib/monitoring";

export const dynamic = "force-dynamic";

export default async function MonitoringPoliciesPage() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  let policies: MonitoringPolicy[] | null = null;
  try {
    policies = await getMonitoringPolicies(session.sessionToken);
  } catch {
    policies = null;
  }

  return (
    <>
      <header className="enrollment-page-head">
        <div>
          <span>Versioned configuration</span>
          <h1>Monitoring policies</h1>
          <p>
            Read-only policy inventory across global, client, site, and endpoint scopes. The most
            specific definition wins for each check key.
          </p>
        </div>
        <span className="monitoring-readonly-note">Read-only foundation</span>
      </header>

      <section className="setup-boundary-banner">
        <Layers3 aria-hidden="true" size={22} />
        <div>
          <strong>Most-specific-wins inheritance</strong>
          <span>
            Global defaults flow down through client and site scopes. An endpoint-level check can
            override or disable the inherited key without rewriting its parent policy.
          </span>
        </div>
      </section>

      <section className="enrollment-panel">
        <header>
          <div>
            <span>Policy register</span>
            <h2>{policies === null ? "Unavailable" : `${policies.length} policies`}</h2>
            <small>Current revisions only; open a policy for its append-only history.</small>
          </div>
          <Activity aria-hidden="true" size={19} />
        </header>

        {policies === null ? (
          <div className="enrollment-empty" role="alert">
            <Activity size={24} />
            <h3>Monitoring policies could not be loaded</h3>
            <p>No policies are shown because the server response could not be verified.</p>
          </div>
        ) : policies.length === 0 ? (
          <div className="enrollment-empty">
            <Activity size={24} />
            <h3>No monitoring policies yet</h3>
            <p>The policy contract is ready; an operator can create the first policy through the API.</p>
          </div>
        ) : (
          <div className="enrollment-table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Policy</th>
                  <th>Scope</th>
                  <th>Status</th>
                  <th>Checks</th>
                  <th>Revision</th>
                  <th>Created (UTC)</th>
                </tr>
              </thead>
              <tbody>
                {policies.map((policy) => (
                  <tr key={policy.id}>
                    <td>
                      <Link href={`/monitoring/${encodeURIComponent(policy.id)}`}>{policy.name}</Link>
                      <code>{policy.id}</code>
                    </td>
                    <td>
                      <strong>{formatMonitoringScope(policy.scope)}</strong>
                      <code>{policy.scope_id ?? "All managed endpoints"}</code>
                    </td>
                    <td>
                      <span className={`monitoring-status ${policy.enabled ? "enabled" : "disabled"}`}>
                        {policy.enabled ? "Enabled" : "Disabled"}
                      </span>
                    </td>
                    <td>{policy.check_count}</td>
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
