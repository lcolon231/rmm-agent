// SPDX-License-Identifier: AGPL-3.0-only

import { BellRing, CheckCircle2 } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";

import { getDashboardSession } from "@/lib/dashboard-session";
import { formatMonitoringTimestamp, type MonitoringAlert } from "@/lib/monitoring-core";
import { getMonitoringAlerts } from "@/lib/monitoring";

export const dynamic = "force-dynamic";

export default async function AlertsPage() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  let alerts: MonitoringAlert[] | null = null;
  const alertResult = await Promise.allSettled([getMonitoringAlerts(session.sessionToken)]);
  if (alertResult[0].status === "fulfilled") alerts = alertResult[0].value;
  const activeAlerts = alerts?.filter((alert) => alert.state !== "resolved") ?? [];
  const resolvedAlerts = alerts?.filter((alert) => alert.state === "resolved") ?? [];

  return (
    <>
      <header className="enrollment-page-head">
        <div>
          <span>Technician queue</span>
          <h1>Alerts</h1>
          <p>
            Active monitoring alerts across every managed endpoint. Acknowledgement, assignment,
            comments, and resolution are preserved in immutable history.
          </p>
        </div>
        <span className="monitoring-readonly-note">Live queue</span>
      </header>

      <section className="enrollment-panel monitoring-alert-panel">
        <header>
          <div><span>Active</span><h2>{alerts === null ? "Unavailable" : `${activeAlerts.length} active alerts`}</h2><small>Healthy checks and resolved alerts do not appear here.</small></div>
          <BellRing aria-hidden="true" size={19} />
        </header>
        {alerts === null ? <div className="enrollment-empty" role="alert"><BellRing size={24} /><h3>Alerts could not be loaded</h3><p>No alert data is shown because the response could not be verified.</p></div>
          : activeAlerts.length === 0 ? <div className="enrollment-empty"><CheckCircle2 size={24} /><h3>No active alerts</h3><p>Every monitored check is healthy or its alert has been resolved.</p></div>
          : <div className="enrollment-table-wrap"><table><thead><tr><th>Check</th><th>State</th><th>Latest result</th><th>Occurrences</th><th>Assigned to</th><th>Last observed</th></tr></thead>
            <tbody>{activeAlerts.map((alert) => <tr key={alert.id}><td><Link href={`/alerts/${encodeURIComponent(alert.id)}`}>{alert.check_key.replaceAll("_", " ")}</Link><code>{alert.agent_id}</code></td><td><span className={`alert-state-chip ${alert.state}`}>{alert.state}</span></td><td>{alert.last_result_status}</td><td>{alert.occurrence_count}</td><td>{alert.assigned_to_email ?? "Unassigned"}</td><td>{alert.last_observed_at ? formatMonitoringTimestamp(alert.last_observed_at) : "Unavailable"}</td></tr>)}</tbody>
          </table></div>}
      </section>

      {resolvedAlerts.length > 0 ? (
        <section className="enrollment-panel">
          <header>
            <div><span>History</span><h2>{`${resolvedAlerts.length} resolved`}</h2><small>Recently resolved alerts remain viewable for their append-only history.</small></div>
            <CheckCircle2 aria-hidden="true" size={19} />
          </header>
          <div className="enrollment-table-wrap"><table><thead><tr><th>Check</th><th>State</th><th>Latest result</th><th>Occurrences</th><th>Resolved</th></tr></thead>
            <tbody>{resolvedAlerts.map((alert) => <tr key={alert.id}><td><Link href={`/alerts/${encodeURIComponent(alert.id)}`}>{alert.check_key.replaceAll("_", " ")}</Link><code>{alert.agent_id}</code></td><td><span className={`alert-state-chip ${alert.state}`}>{alert.state}</span></td><td>{alert.last_result_status}</td><td>{alert.total_occurrence_count}</td><td>{alert.resolved_at ? formatMonitoringTimestamp(alert.resolved_at) : "Unavailable"}</td></tr>)}</tbody>
          </table></div>
        </section>
      ) : null}
    </>
  );
}
