// SPDX-License-Identifier: AGPL-3.0-only

import { Activity, BellRing, Layers3, Webhook } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";

import { getDashboardSession } from "@/lib/dashboard-session";
import {
  formatMonitoringScope,
  formatMonitoringTimestamp,
  type MonitoringPolicy,
  type MonitoringAlert,
} from "@/lib/monitoring-core";
import { getMonitoringAlerts, getMonitoringPolicies } from "@/lib/monitoring";

export const dynamic = "force-dynamic";

export default async function MonitoringPoliciesPage() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  let policies: MonitoringPolicy[] | null = null;
  let alerts: MonitoringAlert[] | null = null;
  const [policyResult, alertResult] = await Promise.allSettled([
    getMonitoringPolicies(session.sessionToken), getMonitoringAlerts(session.sessionToken),
  ]);
  if (policyResult.status === "fulfilled") policies = policyResult.value;
  if (alertResult.status === "fulfilled") alerts = alertResult.value;
  const activeAlerts = alerts?.filter((alert) => alert.state !== "resolved") ?? [];

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

      <Link className="monitoring-webhook-entry" href="/monitoring/webhooks">
        <span><Webhook aria-hidden="true" size={20} /></span>
        <div><strong>Signed webhook destinations</strong><small>Configure public HTTPS receivers, rotate signing secrets, and inspect delivery health.</small></div>
        <b>Manage destinations →</b>
      </Link>

      <section className="enrollment-panel monitoring-alert-panel">
        <header>
          <div><span>Technician queue</span><h2>{alerts === null ? "Unavailable" : `${activeAlerts.length} active alerts`}</h2><small>Acknowledgement, assignment, comments, and resolution are preserved in immutable history.</small></div>
          <Link className="panel-link" href="/alerts">View full queue <BellRing aria-hidden="true" size={15} /></Link>
        </header>
        {alerts === null ? <div className="enrollment-empty" role="alert"><BellRing size={24} /><h3>Alerts could not be loaded</h3><p>No alert data is shown because the response could not be verified.</p></div>
          : activeAlerts.length === 0 ? <div className="enrollment-empty"><BellRing size={24} /><h3>No active alerts</h3><p>Healthy checks and resolved alerts do not appear in the active queue.</p></div>
          : <div className="enrollment-table-wrap"><table><thead><tr><th>Check</th><th>State</th><th>Latest result</th><th>Occurrences</th><th>Assigned to</th><th>Last observed</th></tr></thead>
            <tbody>{activeAlerts.map((alert) => <tr key={alert.id}><td><Link href={`/alerts/${encodeURIComponent(alert.id)}`}>{alert.check_key.replaceAll("_", " ")}</Link><code>{alert.agent_id}</code></td><td><span className={`alert-state-chip ${alert.state}`}>{alert.state}</span></td><td>{alert.last_result_status}</td><td>{alert.occurrence_count}</td><td>{alert.assigned_to_email ?? "Unassigned"}</td><td>{alert.last_observed_at ? formatMonitoringTimestamp(alert.last_observed_at) : "Unavailable"}</td></tr>)}</tbody>
          </table></div>}
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
