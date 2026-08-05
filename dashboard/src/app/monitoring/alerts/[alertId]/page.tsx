// SPDX-License-Identifier: AGPL-3.0-only

import { Activity, ArrowLeft, BellRing, Clock3, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";

import { AlertActions } from "@/components/alert-actions";
import { EmailDeliveryHistory } from "@/components/email-delivery-history";
import { getDashboardSession } from "@/lib/dashboard-session";
import {
  getAlertAssignees,
  getAlertEmailDeliveries,
  getMonitoringAlert,
} from "@/lib/monitoring";
import { formatAlertEventType, formatMonitoringTimestamp } from "@/lib/monitoring-core";
import { NodelinkApiError } from "@/lib/nodelink-api";

export const dynamic = "force-dynamic";

export default async function AlertDetailPage({ params }: { params: Promise<{ alertId: string }> }) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");
  const { alertId } = await params;
  let alert;
  let deliveries;
  let assignees;
  try {
    [alert, deliveries, assignees] = await Promise.all([
      getMonitoringAlert(session.sessionToken, alertId),
      getAlertEmailDeliveries(session.sessionToken, alertId),
      session.operator.role === "readonly"
        ? Promise.resolve([])
        : getAlertAssignees(session.sessionToken).catch(() => []),
    ]);
  } catch (error) {
    if (error instanceof NodelinkApiError && error.status === 404) notFound();
    throw error;
  }

  return (
    <>
      <Link className="detail-back" href="/monitoring"><ArrowLeft size={15} /> Monitoring</Link>
      <header className="enrollment-page-head alert-detail-head">
        <div>
          <span>Alert generation {alert.generation}</span>
          <h1>{alert.check_key.replaceAll("_", " ")}</h1>
          <p>Endpoint <code>{alert.agent_id}</code> · Policy <code>{alert.policy_id}</code></p>
        </div>
        <span className={`alert-state-chip ${alert.state}`}>{alert.state}</span>
      </header>

      <section className="monitoring-summary-grid alert-summary-grid">
        <section><span>Latest result</span><strong>{alert.last_result_status}</strong></section>
        <section><span>Current occurrences</span><strong>{alert.occurrence_count}</strong></section>
        <section><span>Assigned to</span><strong>{alert.assigned_to_email ?? "Unassigned"}</strong></section>
        <section><span>Last observed</span><strong>{alert.last_observed_at ? formatMonitoringTimestamp(alert.last_observed_at) : "Unavailable"}</strong></section>
      </section>

      <AlertActions
        key={`${alert.id}:${alert.version}`}
        alert={{
          id: alert.id,
          state: alert.state,
          version: alert.version,
          assigned_to_operator_id: alert.assigned_to_operator_id,
        }}
        assignees={assignees}
        canManage={session.operator.role !== "readonly"}
      />

      <EmailDeliveryHistory
        key={deliveries.map((item) => `${item.id}:${item.updated_at}`).join("|")}
        initialDeliveries={deliveries}
        canManage={session.operator.role !== "readonly"}
      />

      <section className="enrollment-panel alert-history-panel">
        <header><div><span>Immutable history</span><h2>{alert.events.length} lifecycle events</h2></div><ShieldCheck size={19} /></header>
        {alert.events.length ? (
          <div className="alert-history">
            {alert.events.map((event) => (
              <article key={event.id}>
                <span className="alert-history-icon"><Clock3 size={15} /></span>
                <div>
                  <strong>{formatAlertEventType(event.event_type)}</strong>
                  <p>{event.from_state && event.to_state && event.from_state !== event.to_state
                    ? `${event.from_state} → ${event.to_state}` : event.to_state ?? "Lifecycle evidence"}</p>
                  {event.comment ? <blockquote>{event.comment}{event.comment_redacted ? " (credential-shaped text redacted)" : ""}</blockquote> : null}
                  {event.event_type === "assigned" ? (
                    <p>{event.assigned_to_email ? `Assigned to ${event.assigned_to_email}` : "Assignment cleared"}</p>
                  ) : null}
                </div>
                <small>{event.actor}<br />{formatMonitoringTimestamp(event.created_at)}</small>
              </article>
            ))}
          </div>
        ) : <div className="enrollment-empty"><Activity size={24} /><h3>No lifecycle events</h3></div>}
      </section>

      <section className="enrollment-panel alert-evidence-panel">
        <header><div><span>Check evidence</span><h2>{alert.observations.length} recent observations</h2></div><BellRing size={19} /></header>
        <div className="enrollment-table-wrap"><table><thead><tr><th>Status</th><th>Value</th><th>Evaluated (UTC)</th><th>Ordering</th></tr></thead>
          <tbody>{alert.observations.map((item) => <tr key={item.check_result_id}><td>{item.status}</td><td>{item.value ?? "—"}</td><td>{formatMonitoringTimestamp(item.evaluated_at)}</td><td>{item.out_of_order ? "Late evidence" : "Applied"}</td></tr>)}</tbody>
        </table></div>
      </section>
    </>
  );
}
