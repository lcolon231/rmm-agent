// SPDX-License-Identifier: AGPL-3.0-only

import { AlertTriangle, ArrowRight, KeyRound, MonitorCheck, MonitorOff, ShieldOff } from "lucide-react";
import Link from "next/link";

import { getDashboardSession } from "@/lib/dashboard-session";
import { getEnrollmentDashboard } from "@/lib/enrollment";
import { formatEnrollmentDateTime } from "@/lib/enrollment-core";
import { redirect } from "next/navigation";

export default async function EnrollmentDashboardPage() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");
  const data = await getEnrollmentDashboard(session.sessionToken);
  const cards = [
    { label: "Total agents", value: data.total_agents, icon: MonitorCheck, tone: "blue" },
    { label: "Active agents", value: data.active_agents, icon: MonitorCheck, tone: "teal" },
    { label: "Offline agents", value: data.offline_agents, icon: MonitorOff, tone: "amber" },
    { label: "Revoked agents", value: data.revoked_agents, icon: ShieldOff, tone: "red" },
    { label: "Active tokens", value: data.active_enrollment_tokens, icon: KeyRound, tone: "violet" },
    { label: "Expired tokens", value: data.expired_tokens, icon: KeyRound, tone: "slate" },
  ];
  return (
    <>
      <header className="enrollment-page-head">
        <div><span>Provisioning posture</span><h1>Enrollment dashboard</h1><p>Temporary credentials, endpoint identity, and enrollment evidence in one control surface.</p></div>
        {session.operator.role !== "readonly" ? <Link className="enrollment-primary-link" href="/enrollment/tokens/new"><KeyRound size={17} /> Create token</Link> : null}
      </header>
      <section className="enrollment-stat-grid" aria-label="Enrollment status">
        {cards.map(({ icon: Icon, ...card }) => <article className={`enrollment-stat ${card.tone}`} key={card.label}><Icon size={19} /><span>{card.label}</span><strong>{card.value}</strong></article>)}
      </section>
      {data.recent_enrollment_failures > 0 ? <div className="enrollment-alert"><AlertTriangle size={18} /><span><strong>{data.recent_enrollment_failures} failed enrollment attempts</strong> were recorded in the last 24 hours.</span><Link href="/enrollment/audit?event=agent.enrollment_failed">Review</Link></div> : null}
      <section className="enrollment-panel">
        <header><div><span>Latest identities</span><h2>Recently enrolled agents</h2></div><Link href="/enrollment/agents">View inventory <ArrowRight size={15} /></Link></header>
        {data.recently_enrolled_agents.length === 0 ? <div className="enrollment-empty"><MonitorOff size={24} /><h3>No agents enrolled yet</h3><p>Create a short-lived token to provision the first endpoint.</p></div> : (
          <div className="enrollment-table-wrap"><table><thead><tr><th>Agent</th><th>Host</th><th>Environment</th><th>Trust</th><th>Enrolled</th></tr></thead><tbody>
            {data.recently_enrolled_agents.map((agent) => <tr key={agent.id}><td><Link href={`/enrollment/agents/${agent.id}`}>{agent.name || agent.hostname}</Link><code>{agent.id.slice(0, 8)}</code></td><td>{agent.hostname}</td><td>{agent.environment ?? "Unassigned"}</td><td><span className={`enrollment-badge ${agent.trust_state}`}>{agent.trust_state}</span></td><td>{formatEnrollmentDateTime(agent.enrolled_at)}</td></tr>)}
          </tbody></table></div>
        )}
      </section>
    </>
  );
}
