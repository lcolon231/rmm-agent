// SPDX-License-Identifier: AGPL-3.0-only

import { Activity, ArrowLeft, BellRing, Clock3, PackageCheck, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";

import { AlertActions } from "@/components/alert-actions";
import { EmailDeliveryHistory } from "@/components/email-delivery-history";
import { WebhookDeliveryHistory } from "@/components/webhook-delivery-history";
import { getDashboardSession } from "@/lib/dashboard-session";
import {
  getAlertAssignees,
  getAlertEmailDeliveries,
  getAlertWebhookDeliveries,
  getMonitoringAlert,
} from "@/lib/monitoring";
import {
  formatAlertEventType,
  formatMonitoringTimestamp,
  rebootCorrelationPresentation,
} from "@/lib/monitoring-core";
import { NodelinkApiError } from "@/lib/nodelink-api";

export const dynamic = "force-dynamic";

export default async function AlertDetailPage({ params }: { params: Promise<{ alertId: string }> }) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");
  const { alertId } = await params;
  let alert;
  let deliveries;
  let webhookDeliveries;
  let assignees;
  try {
    [alert, deliveries, webhookDeliveries, assignees] = await Promise.all([
      getMonitoringAlert(session.sessionToken, alertId),
      getAlertEmailDeliveries(session.sessionToken, alertId),
      getAlertWebhookDeliveries(session.sessionToken, alertId),
      session.operator.role === "readonly"
        ? Promise.resolve([])
        : getAlertAssignees(session.sessionToken).catch(() => []),
    ]);
  } catch (error) {
    if (error instanceof NodelinkApiError && error.status === 404) notFound();
    throw error;
  }
  const rebootPresentation = rebootCorrelationPresentation(
    alert.last_result_detail,
    alert.reboot_cause,
  );

  return (
    <>
      <Link className="detail-back" href="/alerts"><ArrowLeft size={15} /> Alerts</Link>
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

      {rebootPresentation ? (
        <section className={`enrollment-panel reboot-correlation-panel ${rebootPresentation.state}`}>
          <header>
            <div><span>Restart attribution</span><h2>Windows Update correlation</h2></div>
            <PackageCheck size={19} />
          </header>
          <div className="reboot-correlation-status">
            <strong>{rebootPresentation.title}</strong>
            <p>{rebootPresentation.summary}</p>
          </div>
          {alert.reboot_cause ? (
            <>
              <dl className="reboot-correlation-meta">
                <div><dt>System reboot flag</dt><dd>{alert.reboot_cause.system_reboot_required === null ? "Unavailable" : alert.reboot_cause.system_reboot_required ? "Reported" : "Not reported"}</dd></div>
                <div><dt>Update scan</dt><dd>{alert.reboot_cause.scanned_at ? formatMonitoringTimestamp(alert.reboot_cause.scanned_at) : "Unavailable"}</dd></div>
                <div><dt>Snapshot received</dt><dd>{formatMonitoringTimestamp(alert.reboot_cause.snapshot_received_at)}</dd></div>
              </dl>
              <div className="reboot-correlation-evidence">
                <article>
                  <header><span>Reboot-flagged updates</span><strong>{alert.reboot_cause.reboot_flagged_updates.length}</strong></header>
                  {alert.reboot_cause.reboot_flagged_updates.length ? (
                    <ul>{alert.reboot_cause.reboot_flagged_updates.map((update, index) => (
                      <li key={`${update.update_id ?? update.kb_id ?? update.title}:${index}`}>
                        <strong>{update.kb_id ?? "No KB"}</strong><span>{update.title}</span>
                      </li>
                    ))}</ul>
                  ) : <p>No update entries were flagged as requiring a restart.</p>}
                </article>
                <article>
                  <header><span>Recent installs · 7-day correlation</span><strong>{alert.reboot_cause.recent_installs.length}</strong></header>
                  {alert.reboot_cause.recent_installs.length ? (
                    <ul>{alert.reboot_cause.recent_installs.map((update, index) => (
                      <li key={`${update.update_id ?? update.kb_id ?? update.title ?? "install"}:${index}`}>
                        <strong>{update.kb_id ?? "No KB"}</strong>
                        <span>{update.title ?? "Untitled update"}{update.installed_on ? ` · ${formatMonitoringTimestamp(update.installed_on)}` : ""}</span>
                      </li>
                    ))}</ul>
                  ) : <p>No installs were recorded inside the correlation window.</p>}
                </article>
              </div>
              <p className="reboot-correlation-note">Inventory proximity is supporting evidence only; it does not establish which event caused the pending restart.</p>
            </>
          ) : null}
        </section>
      ) : null}

      <EmailDeliveryHistory
        key={deliveries.map((item) => `${item.id}:${item.updated_at}`).join("|")}
        initialDeliveries={deliveries}
        canManage={session.operator.role !== "readonly"}
      />

      <WebhookDeliveryHistory
        key={webhookDeliveries.map((item) => `${item.id}:${item.updated_at}`).join("|")}
        initialDeliveries={webhookDeliveries}
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
