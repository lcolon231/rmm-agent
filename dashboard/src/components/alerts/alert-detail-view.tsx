// SPDX-License-Identifier: AGPL-3.0-only

import { Mail, Webhook } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import {
  formatMonitoringTimestamp,
  rebootCorrelationPresentation,
  type AlertAssignee,
  type AlertEmailDelivery,
  type AlertEvent,
  type AlertWebhookDelivery,
  type MonitoringAlertDetail,
  type RebootCorrelationPresentation,
} from "@/lib/monitoring-core";
import {
  alertEventTone,
  alertEventWord,
  alertRiskTone,
  alertSeverityWord,
  alertStateWord,
  alertTitle,
  emailDeliveryWord,
  webhookDeliveryWord,
  type AlertTab,
  type ViewTone,
} from "@/lib/monitoring-view-core";

import { Card } from "../monitoring/detail-card";
import { AlertActionsProvider, AlertHeaderActions, AlertWorkPanel } from "../alert-actions";
import { EmailDeliveryHistory } from "../email-delivery-history";
import { PageHeader, PageStack } from "../shell/page-header";
import { cx, focusRing } from "../ui/cx";
import { DefinitionList } from "../ui/drawer";
import { EmptyState } from "../ui/states";
import { StatusBadge, toneStyles } from "../ui/status-badge";
import { TabNav } from "../ui/tab-nav";
import { WebhookDeliveryHistory } from "../webhook-delivery-history";

type AlertDetailViewProps = {
  alert: MonitoringAlertDetail;
  emailDeliveries: AlertEmailDelivery[];
  webhookDeliveries: AlertWebhookDelivery[];
  assignees: AlertAssignee[];
  canManage: boolean;
  tab: AlertTab;
};

const linkClass = cx("rounded text-(--primary-strong) no-underline hover:underline", focusRing);

function when(value: string | null) {
  return value ? formatMonitoringTimestamp(value) : "Not recorded";
}

function actorName(actor: string) {
  return actor === "system" ? "NodeLink monitoring" : <span className="font-(family-name:--font-data)">{actor}</span>;
}

function stateChange(event: AlertEvent) {
  if (!event.from_state || !event.to_state || event.from_state === event.to_state) return null;
  return `${alertStateWord(event.from_state).label} → ${alertStateWord(event.to_state).label}`;
}

type TimelineEntry = { id: string; at: string; tone: ViewTone; title: ReactNode; lines: ReactNode[]; who: ReactNode };

/** Lifecycle events and every notification queued for them, oldest first. */
function timelineEntries(alert: MonitoringAlertDetail, emails: AlertEmailDelivery[], webhooks: AlertWebhookDelivery[]): TimelineEntry[] {
  const entries: TimelineEntry[] = [
    ...alert.events.map((event) => ({
      id: `event:${event.id}`,
      at: event.created_at,
      tone: alertEventTone(event.event_type),
      title: alertEventWord(event.event_type),
      lines: [
        stateChange(event),
        event.event_type === "assigned" ? (event.assigned_to_email ? `Assigned to ${event.assigned_to_email}` : "Assignment cleared") : null,
        event.comment ? (
          <q key="comment" className="text-(--slate)">
            {event.comment}
            {event.comment_redacted ? " (text that looked like a password was removed)" : ""}
          </q>
        ) : null,
      ].filter(Boolean) as ReactNode[],
      who: actorName(event.actor),
    })),
    ...emails.map((delivery) => {
      const word = emailDeliveryWord(delivery.status);
      return {
        id: `email:${delivery.id}`,
        at: delivery.created_at,
        tone: word.tone,
        title: (
          <>
            Email to <span className="font-(family-name:--font-data)">{delivery.recipient}</span> · {word.label.toLowerCase()}
          </>
        ),
        lines: [`For: ${alertEventWord(delivery.event_type).toLowerCase()} · ${delivery.attempt_count} of ${delivery.max_attempts} attempts`],
        who: "Email",
      };
    }),
    ...webhooks.map((delivery) => {
      const word = webhookDeliveryWord(delivery.status);
      return {
        id: `webhook:${delivery.id}`,
        at: delivery.created_at,
        tone: word.tone,
        title: `Webhook to ${delivery.endpoint_name} · ${word.label.toLowerCase()}`,
        lines: [`For: ${alertEventWord(delivery.event_type).toLowerCase()} · ${delivery.attempt_count} of ${delivery.max_attempts} attempts`],
        who: "Webhook",
      };
    }),
  ];
  return entries.sort((a, b) => Date.parse(a.at) - Date.parse(b.at) || a.id.localeCompare(b.id));
}

function Timeline({ entries }: { entries: TimelineEntry[] }) {
  if (entries.length === 0) return <EmptyState title="Nothing recorded yet" body="No changes or notifications have been recorded for this alert." />;
  return (
    <ol className="m-0 grid list-none gap-0 p-0">
      {entries.map((entry) => {
        const tone = toneStyles[entry.tone];
        const Icon = tone.icon;
        return (
          <li key={entry.id} className="flex gap-3 border-t border-(--line) px-5 py-3.5 first:border-t-0">
            <span className={cx("flex size-6 shrink-0 items-center justify-center rounded-full", tone.surface, tone.text)}>
              <Icon size={14} aria-hidden="true" />
            </span>
            <div className="grid min-w-0 flex-1 gap-0.5">
              <span className="font-semibold break-words text-(--ink)">{entry.title}</span>
              {entry.lines.map((line, index) => (
                <span key={index} className="text-[13px] break-words text-(--muted)">
                  {line}
                </span>
              ))}
              <span className="text-xs text-(--muted)">{entry.who}</span>
            </div>
            <time className="shrink-0 text-xs text-(--muted)">{formatMonitoringTimestamp(entry.at)}</time>
          </li>
        );
      })}
    </ol>
  );
}

function RebootCard({ alert, presentation }: { alert: MonitoringAlertDetail; presentation: RebootCorrelationPresentation }) {
  const cause = alert.reboot_cause;
  const sources = presentation.sources;
  return (
    <Card title="Why a restart is waiting" sub={presentation.title}>
      <div className="grid gap-4 px-5 py-4 text-sm text-(--slate)">
        <p className="m-0">{presentation.summary}</p>
        {sources ? (
          <DefinitionList
            items={[
              { term: "Windows Update", value: sources.windows_update ? "Restart required" : "Not set" },
              { term: "Component servicing", value: sources.component_based_servicing ? "Restart required" : "Not set" },
              {
                term: "Files waiting to be replaced",
                value: !sources.pending_file_rename
                  ? "Not set"
                  : sources.pending_file_rename_count === null
                    ? "Restart required · count unavailable"
                    : `Restart required · ${sources.pending_file_rename_count} queued`,
              },
            ]}
          />
        ) : null}
        <div className="grid gap-1 rounded-lg bg-(--fog) px-4 py-3">
          <strong className="text-(--ink)">Related updates: {presentation.correlation.title}</strong>
          <p className="m-0">{presentation.correlation.summary}</p>
        </div>
        {cause?.snapshot_received_at ? (
          <>
            <DefinitionList
              items={[
                {
                  term: "System restart flag",
                  value: cause.system_reboot_required === null ? "Unavailable" : cause.system_reboot_required ? "Reported" : "Not reported",
                },
                { term: "Update scan", value: when(cause.scanned_at) },
                { term: "Update list received", value: formatMonitoringTimestamp(cause.snapshot_received_at) },
              ]}
            />
            <div className="grid gap-4 min-[700px]:grid-cols-2">
              <div className="grid content-start gap-2">
                <h3 className="m-0 text-sm font-semibold text-(--ink)">Updates that ask for a restart ({cause.reboot_flagged_updates.length})</h3>
                {cause.reboot_flagged_updates.length ? (
                  <ul className="m-0 grid gap-1.5 pl-5">
                    {cause.reboot_flagged_updates.map((update, index) => (
                      <li key={`${update.update_id ?? update.kb_id ?? update.title}:${index}`}>
                        <span className="font-(family-name:--font-data) text-[13px]">{update.kb_id ?? "No KB"}</span> {update.title}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="m-0 text-[13px] text-(--muted)">No update is marked as needing a restart.</p>
                )}
              </div>
              <div className="grid content-start gap-2">
                <h3 className="m-0 text-sm font-semibold text-(--ink)">Installed in the last 7 days ({cause.recent_installs.length})</h3>
                {cause.recent_installs.length ? (
                  <ul className="m-0 grid gap-1.5 pl-5">
                    {cause.recent_installs.map((update, index) => (
                      <li key={`${update.update_id ?? update.kb_id ?? update.title ?? "install"}:${index}`}>
                        <span className="font-(family-name:--font-data) text-[13px]">{update.kb_id ?? "No KB"}</span> {update.title ?? "Untitled update"}
                        {update.installed_on ? ` · ${formatMonitoringTimestamp(update.installed_on)}` : ""}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="m-0 text-[13px] text-(--muted)">No installs were recorded in that time.</p>
                )}
              </div>
            </div>
            <p className="m-0 text-xs text-(--muted)">An update installed around the same time is a clue, not proof of what caused the restart.</p>
          </>
        ) : null}
      </div>
    </Card>
  );
}

function SummaryTab({ alert }: { alert: MonitoringAlertDetail }) {
  const tone = toneStyles[alertRiskTone(alert)];
  const Icon = tone.icon;
  const severity = alertSeverityWord(alert.last_result_status);
  const reboot = rebootCorrelationPresentation(alert.last_result_detail, alert.reboot_cause);
  return (
    <>
      <div role="status" className={cx("flex items-start gap-3 rounded-lg px-4 py-3", tone.surface)}>
        <Icon size={18} aria-hidden="true" className={cx("mt-0.5 shrink-0", tone.text)} />
        <p className="m-0 grid gap-0.5 text-sm">
          <span className={cx("font-semibold", tone.text)}>{alertStateWord(alert.state).label}</span>
          <span className="text-(--slate)">
            {alert.state === "resolved"
              ? `Resolved ${when(alert.resolved_at)}.`
              : `The latest check result is ${severity.label.toLowerCase()}${alert.last_value === null ? "" : ` (reading ${alert.last_value})`}, seen ${alert.occurrence_count} ${alert.occurrence_count === 1 ? "time" : "times"} in a row.`}
          </span>
        </p>
      </div>
      {reboot ? <RebootCard alert={alert} presentation={reboot} /> : null}
      <Card title="What was measured" sub="The most recent check results for this alert.">
        {alert.observations.length ? (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[520px] border-collapse text-left text-sm">
              <caption className="sr-only">Recent check results</caption>
              <thead className="bg-(--fog)">
                <tr>
                  {["Result", "Reading", "Checked", "Order"].map((label) => (
                    <th key={label} scope="col" className="px-5 py-2.5 text-xs font-semibold text-(--muted)">
                      {label}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {alert.observations.map((item) => {
                  const word = alertSeverityWord(item.status);
                  return (
                    <tr key={item.check_result_id} className="border-t border-(--line) text-(--slate)">
                      <td className="px-5 py-3">
                        <StatusBadge tone={word.tone}>{word.label}</StatusBadge>
                      </td>
                      <td className="px-5 py-3">{item.value ?? "—"}</td>
                      <td className="px-5 py-3">{formatMonitoringTimestamp(item.evaluated_at)}</td>
                      <td className="px-5 py-3">{item.out_of_order ? "Arrived late" : "In order"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState title="No check results" body="No recent check results were returned for this alert." />
        )}
      </Card>
    </>
  );
}

function NotificationsTab({ alert, emails, webhooks, canManage }: { alert: MonitoringAlertDetail; emails: AlertEmailDelivery[]; webhooks: AlertWebhookDelivery[]; canManage: boolean }) {
  return (
    <>
      <p className="m-0 flex items-center gap-2 text-sm text-(--muted)">
        <Mail size={16} aria-hidden="true" />
        <Webhook size={16} aria-hidden="true" />
        Who NodeLink told about {alertTitle(alert.check_key).toLowerCase()}, and whether it got through.
      </p>
      <EmailDeliveryHistory key={emails.map((item) => `${item.id}:${item.updated_at}`).join("|")} initialDeliveries={emails} canManage={canManage} />
      <WebhookDeliveryHistory key={webhooks.map((item) => `${item.id}:${item.updated_at}`).join("|")} initialDeliveries={webhooks} canManage={canManage} />
    </>
  );
}

function Glance({ alert }: { alert: MonitoringAlertDetail }) {
  return (
    <Card title="At a glance">
      <div className="px-5 py-4 text-sm">
        <DefinitionList
          items={[
            { term: "Severity", value: alertSeverityWord(alert.last_result_status).label },
            { term: "State", value: alertStateWord(alert.state).label },
            { term: "Device", value: <Link className={cx(linkClass, "font-(family-name:--font-data)")} href={`/endpoints/${encodeURIComponent(alert.agent_id)}`}>{alert.agent_id}</Link> },
            { term: "Policy", value: <Link className={cx(linkClass, "font-(family-name:--font-data)")} href={`/monitoring/${encodeURIComponent(alert.policy_id)}`}>{alert.policy_id}</Link> },
            { term: "Opened", value: when(alert.opened_at ?? alert.first_opened_at) },
            { term: "Last seen", value: when(alert.last_observed_at) },
            { term: "Assigned to", value: alert.assigned_to_email ?? "Nobody" },
            { term: "Times seen", value: `${alert.occurrence_count} this time · ${alert.total_occurrence_count} in total` },
          ]}
        />
      </div>
    </Card>
  );
}

function RecordCard({ alert }: { alert: MonitoringAlertDetail }) {
  // Events arrive newest first.
  const recent = alert.events.slice(0, 5);
  return (
    <Card title="Record" sub="Who did what, and when">
      {recent.length ? (
        <ul className="m-0 grid list-none gap-2.5 px-5 py-4 text-[13px]">
          {recent.map((event) => (
            <li key={event.id} className="grid gap-0.5">
              <span className="text-(--ink)">
                {alertEventWord(event.event_type)} · {actorName(event.actor)}
              </span>
              <time className="text-xs text-(--muted)">{formatMonitoringTimestamp(event.created_at)}</time>
            </li>
          ))}
        </ul>
      ) : (
        <p className="m-0 px-5 py-4 text-[13px] text-(--muted)">Nothing has been recorded for this alert yet.</p>
      )}
    </Card>
  );
}

export function AlertDetailView({ alert, emailDeliveries, webhookDeliveries, assignees, canManage, tab }: AlertDetailViewProps) {
  const base = `/alerts/${encodeURIComponent(alert.id)}`;
  const state = alertStateWord(alert.state);
  const title = alertTitle(alert.check_key);
  const notificationCount = emailDeliveries.length + webhookDeliveries.length;
  return (
    <AlertActionsProvider
      key={`${alert.id}:${alert.version}`}
      alert={{ id: alert.id, state: alert.state, version: alert.version, assigned_to_operator_id: alert.assigned_to_operator_id }}
      assignees={assignees}
      canManage={canManage}
    >
      <PageStack>
        <PageHeader
          breadcrumb={[{ label: "Devices" }, { label: "Alerts", href: "/alerts" }, { label: title }]}
          title={title}
          status={<StatusBadge tone={state.tone}>{state.label}</StatusBadge>}
          description={
            <>
              Raised on device <span className="font-(family-name:--font-data)">{alert.agent_id}</span> by a monitoring policy. Opened {when(alert.opened_at ?? alert.first_opened_at)}.
            </>
          }
          actions={<AlertHeaderActions />}
        />
        <TabNav
          label="Alert sections"
          tabs={[
            { label: "Summary", href: base, current: tab === "summary" },
            { label: `Timeline (${alert.events.length + notificationCount})`, href: `${base}?tab=timeline`, current: tab === "timeline" },
            { label: `Notifications (${notificationCount})`, href: `${base}?tab=notifications`, current: tab === "notifications" },
          ]}
        />
        <div className="grid items-start gap-6 min-[1100px]:grid-cols-[minmax(0,2fr)_minmax(280px,1fr)]">
          <div className="grid min-w-0 gap-6">
            {tab === "timeline" ? (
              <Card title="Timeline" sub="Loaded alert events and delivery attempts, oldest first.">
                <Timeline entries={timelineEntries(alert, emailDeliveries, webhookDeliveries)} />
              </Card>
            ) : tab === "notifications" ? (
              <NotificationsTab alert={alert} emails={emailDeliveries} webhooks={webhookDeliveries} canManage={canManage} />
            ) : (
              <SummaryTab alert={alert} />
            )}
          </div>
          <aside aria-label="Alert facts" className="grid min-w-0 gap-6">
            <AlertWorkPanel />
            <Glance alert={alert} />
            <RecordCard alert={alert} />
          </aside>
        </div>
      </PageStack>
    </AlertActionsProvider>
  );
}

