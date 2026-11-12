// SPDX-License-Identifier: AGPL-3.0-only

import { History } from "lucide-react";
import { notFound, redirect } from "next/navigation";

import { StatusNote } from "@/components/admin/admin-ui";
import { Card, Mono } from "@/components/admin/card";
import { EnrollmentHeader } from "@/components/enrollment/enrollment-header";
import { RevokeAction } from "@/components/enrollment/revoke-action";
import { PageStack } from "@/components/shell/page-header";
import { DefinitionList } from "@/components/ui/drawer";
import { StatusBadge } from "@/components/ui/status-badge";
import { agentCheckInBadge, agentTrustBadge } from "@/lib/admin-screens-core";
import { getDashboardSession } from "@/lib/dashboard-session";
import { formatAgentVersion } from "@/lib/endpoint-detail-core";
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
  const name = agent.name || agent.hostname;
  const trust = agentTrustBadge(agent.trust_state);
  const checkIn = agentCheckInBadge(agent.status);

  return (
    <PageStack>
      <EnrollmentHeader
        tab="agents"
        role={session.operator.role}
        trail={[{ label: "Agents", href: "/enrollment/agents" }, { label: name }]}
        title={<span className="font-(family-name:--font-data)">{name}</span>}
        status={<StatusBadge tone={trust.tone}>{trust.label}</StatusBadge>}
        description={`${agent.hostname} · ${agent.os || "Unknown system"} · enrolled ${formatEnrollmentDateTime(agent.enrolled_at, "Never", true)}`}
        actions={
          session.operator.role === "admin" && agent.trust_state !== "revoked" ? (
            <RevokeAction endpoint={`/api/enrollment-agents/${agent.id}/revoke`} kind="agent" label="Revoke agent" subject={name} />
          ) : null
        }
      />
      <div className="grid gap-6 min-[1100px]:grid-cols-[minmax(0,2fr)_minmax(280px,1fr)]">
        <div className="grid content-start gap-6">
          <StatusNote tone={trust.tone === "ok" ? "ok" : trust.tone === "crit" ? "crit" : "warn"} title={trust.label}>
            {agent.trust_state_reason ?? trust.detail}
          </StatusNote>
          <Card title="Enrollment record">
            <DefinitionList
              items={[
                { term: "Agent ID", value: <Mono>{agent.id}</Mono> },
                { term: "Site ID", value: <Mono>{agent.site_id}</Mono> },
                { term: "Enrollment token ID", value: agent.enrolled_by_token_id ? <Mono>{agent.enrolled_by_token_id}</Mono> : "Not recorded (enrolled before tokens were tracked)" },
                { term: "Owner user ID", value: agent.owner_user_id ?? "Unassigned" },
                { term: "Environment", value: agent.environment ?? "Unassigned" },
                { term: "Operating system", value: `${agent.os} ${agent.os_version}`.trim() || "Unknown" },
                { term: "Architecture", value: agent.architecture || "Unknown" },
                { term: "Labels", value: agent.labels.length ? agent.labels.join(", ") : "No labels" },
              ]}
            />
          </Card>
          <Card title="Enrollment and trust history" sub="Audit entries that reference this agent" action={<History size={18} aria-hidden="true" className="text-(--muted)" />} bodyClassName="px-5 py-4">
            {events.items.length === 0 ? (
              <p className="m-0 text-sm text-(--muted)">No audit entries reference this agent.</p>
            ) : (
              <ol className="m-0 grid list-none gap-3 p-0">
                {events.items.map((event) => (
                  <li key={event.id} className="flex flex-wrap items-start justify-between gap-3 border-b border-(--line) pb-3 last:border-b-0 last:pb-0">
                    <span className="grid gap-0.5">
                      <span className="font-semibold text-(--ink)">{event.action.replaceAll(".", " ").replaceAll("_", " ")}</span>
                      <span className="text-xs text-(--muted)">
                        {event.actor} · entry {event.seq ?? "without sequence number"}
                      </span>
                    </span>
                    <span className="text-xs text-(--muted)">{formatEnrollmentDateTime(event.ts, "Never", true)}</span>
                  </li>
                ))}
              </ol>
            )}
          </Card>
        </div>
        <div className="grid content-start gap-6">
          <Card title="At a glance">
            <DefinitionList
              items={[
                { term: "Trust", value: <StatusBadge tone={trust.tone}>{trust.label}</StatusBadge> },
                { term: "Check-in", value: <StatusBadge tone={checkIn.tone}>{checkIn.label}</StatusBadge> },
                { term: "Last check-in", value: formatEnrollmentDateTime(agent.last_seen_at, "Never", true) },
                { term: "Version", value: formatAgentVersion(agent.agent_version, "Unknown") },
                { term: "Fingerprint", value: agent.credential_fingerprint ? <Mono>{agent.credential_fingerprint}</Mono> : "Not recorded" },
                { term: "Credential issued", value: formatEnrollmentDateTime(agent.credential_issued_at, "Never", true) },
                { term: "Credential expires", value: formatEnrollmentDateTime(agent.credential_expires_at, "No expiry configured", true) },
              ]}
            />
          </Card>
        </div>
      </div>
    </PageStack>
  );
}
