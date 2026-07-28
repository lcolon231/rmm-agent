// SPDX-License-Identifier: AGPL-3.0-only

import { Filter, ListChecks } from "lucide-react";
import { redirect } from "next/navigation";

import { getDashboardSession } from "@/lib/dashboard-session";
import { getAuditEvents } from "@/lib/enrollment";
import { formatEnrollmentDateTime } from "@/lib/enrollment-core";

const eventOptions = [
  "enrollment_token.created",
  "enrollment_token.revoked",
  "agent.enrolled",
  "agent.enrollment_failed",
  "agent.credential_renewed",
  "agent.revoked",
];

export default async function EnrollmentAuditPage({ searchParams }: { searchParams: Promise<{ event?: string; page?: string }> }) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");
  const query = await searchParams;
  const eventType = eventOptions.includes(query.event ?? "") ? query.event : undefined;
  const page = /^\d+$/.test(query.page ?? "") ? Math.max(1, Number(query.page)) : 1;
  const data = await getAuditEvents(session.sessionToken, { eventType, page });
  return (
    <>
      <header className="enrollment-page-head"><div><span>Tamper-evident activity</span><h1>Audit log</h1><p>Token issuance, redemption failures, successful enrollments, credential changes, and revocation.</p></div></header>
      <form className="enrollment-filter" method="get"><label><Filter size={16} /><span className="sr-only">Filter event type</span><select defaultValue={eventType ?? ""} name="event"><option value="">All enrollment events</option>{eventOptions.map((event) => <option key={event} value={event}>{event.replaceAll(".", " ")}</option>)}</select></label><button type="submit">Apply</button></form>
      <section className="enrollment-panel">
        <header><div><span>Audit register</span><h2>{data.total} event{data.total === 1 ? "" : "s"}</h2></div><ListChecks size={19} /></header>
        {data.items.length === 0 ? <div className="enrollment-empty"><ListChecks size={24} /><h3>No matching events</h3><p>Change the event filter or enroll an agent to create evidence.</p></div> : (
          <div className="enrollment-table-wrap"><table><thead><tr><th>Sequence</th><th>Event</th><th>Actor</th><th>Agent / token</th><th>Source</th><th>Time</th></tr></thead><tbody>
            {data.items.map((event) => <tr key={event.id}><td><code>{event.seq ?? "legacy"}</code></td><td><strong>{event.action.replaceAll(".", " ")}</strong></td><td>{event.actor}</td><td>{event.agent_id ? <code>{event.agent_id}</code> : event.enrollment_token_id ? <code>{event.enrollment_token_id}</code> : "—"}</td><td>{event.source_ip ?? "Not recorded"}</td><td>{formatEnrollmentDateTime(event.ts, "Never", true)}</td></tr>)}
          </tbody></table></div>
        )}
      </section>
    </>
  );
}
