// SPDX-License-Identifier: AGPL-3.0-only

import { Fingerprint, History, MonitorCog, ShieldCheck } from "lucide-react";
import { notFound, redirect } from "next/navigation";

import { RevokeAction } from "@/components/enrollment/revoke-action";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getAuditEvents, getEnrollmentAgent } from "@/lib/enrollment";
import { formatEnrollmentDateTime } from "@/lib/enrollment-core";
import { NodelinkApiError } from "@/lib/nodelink-api";

export default async function EnrollmentAgentDetailPage({ params }: { params: Promise<{ agentId: string }> }) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");
  const { agentId } = await params;
  let agent;
  try {
    agent = await getEnrollmentAgent(session.sessionToken, agentId);
  } catch (error) {
    if (error instanceof NodelinkApiError && error.status === 404) notFound();
    throw error;
  }
  const events = await getAuditEvents(session.sessionToken, { agentId });
  return (
    <>
      <header className="enrollment-page-head">
        <div><span>Agent identity</span><h1>{agent.name || agent.hostname}</h1><p>{agent.hostname} · {agent.os || "Unknown platform"} · enrolled {formatEnrollmentDateTime(agent.enrolled_at, "Never", true)}</p></div>
        {session.operator.role === "admin" && agent.trust_state !== "revoked" ? <RevokeAction endpoint={`/api/enrollment-agents/${agent.id}/revoke`} label="Revoke agent" subject={agent.name || agent.hostname} /> : null}
      </header>
      <section className="agent-identity-grid">
        <article><MonitorCog size={20} /><span>Runtime status</span><strong>{agent.status}</strong><small>Last heartbeat {formatEnrollmentDateTime(agent.last_seen_at, "Never", true)}</small></article>
        <article><ShieldCheck size={20} /><span>Trust state</span><strong>{agent.trust_state}</strong><small>{agent.trust_state_reason ?? "No trust exception recorded"}</small></article>
        <article><Fingerprint size={20} /><span>Credential fingerprint</span><strong><code>{agent.credential_fingerprint ?? "Legacy / unavailable"}</code></strong><small>Issued {formatEnrollmentDateTime(agent.credential_issued_at, "Never", true)}</small></article>
      </section>
      <section className="enrollment-panel agent-metadata">
        <header><div><span>Enrollment record</span><h2>Assigned metadata</h2></div></header>
        <dl>
          <div><dt>Agent ID</dt><dd><code>{agent.id}</code></dd></div><div><dt>Site ID</dt><dd><code>{agent.site_id}</code></dd></div>
          <div><dt>Enrollment token ID</dt><dd><code>{agent.enrolled_by_token_id ?? "Legacy"}</code></dd></div><div><dt>Owner user ID</dt><dd>{agent.owner_user_id ?? "Unassigned"}</dd></div>
          <div><dt>Environment</dt><dd>{agent.environment ?? "Unassigned"}</dd></div><div><dt>Version</dt><dd>{agent.agent_version || "Unknown"}</dd></div>
          <div><dt>Operating system</dt><dd>{agent.os} {agent.os_version}</dd></div><div><dt>Architecture</dt><dd>{agent.architecture || "Unknown"}</dd></div>
          <div className="wide"><dt>Labels</dt><dd>{agent.labels.length ? agent.labels.join(", ") : "No labels"}</dd></div>
        </dl>
      </section>
      <section className="enrollment-panel">
        <header><div><span>Chain of custody</span><h2>Enrollment and trust history</h2></div><History size={18} /></header>
        {events.items.length === 0 ? <div className="enrollment-empty"><p>No audit events reference this agent.</p></div> : <ol className="audit-timeline">{events.items.map((event) => <li key={event.id}><span /><div><strong>{event.action.replaceAll(".", " ")}</strong><small>{formatEnrollmentDateTime(event.ts, "Never", true)} · {event.actor}</small><code>seq {event.seq ?? "legacy"}</code></div></li>)}</ol>}
      </section>
    </>
  );
}
