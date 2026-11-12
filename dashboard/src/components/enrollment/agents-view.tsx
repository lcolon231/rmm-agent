// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { Monitor } from "lucide-react";

import { ModalLayerProvider, useLayeredDrawer } from "@/components/admin/admin-ui";
import { Mono } from "@/components/admin/card";
import { ButtonLink } from "@/components/ui/button";
import { DataTable, PrimaryCell, TableFooter, type Column } from "@/components/ui/data-table";
import { DefinitionList, Drawer } from "@/components/ui/drawer";
import { EmptyState } from "@/components/ui/states";
import { StatusBadge } from "@/components/ui/status-badge";
import { agentCheckInBadge, agentTrustBadge } from "@/lib/admin-screens-core";
import { formatSeen } from "@/lib/device-status-core";
import { formatAgentVersion } from "@/lib/endpoint-detail-core";
import type { EnrollmentAgent } from "@/lib/enrollment";
import { formatEnrollmentDateTime } from "@/lib/enrollment-core";

import { RevokeAction } from "./revoke-action";

function platform(agent: EnrollmentAgent) {
  return [agent.os, agent.os_version].filter(Boolean).join(" ") || "Unknown system";
}

function lastCheckIn(agent: EnrollmentAgent, now: Date) {
  return agent.last_seen_at ? formatSeen(agent.last_seen_at, now) : "Never";
}

function AgentDrawer({
  agent,
  canRevoke,
  now,
  onClose,
  onRevoked,
}: {
  agent: EnrollmentAgent;
  canRevoke: boolean;
  now: Date;
  onClose: () => void;
  onRevoked: () => void;
}) {
  const trust = agentTrustBadge(agent.trust_state);
  const checkIn = agentCheckInBadge(agent.status);
  return (
    <Drawer
      open
      onClose={onClose}
      context={agent.environment ?? "No environment assigned"}
      title={<Mono>{agent.name || agent.hostname}</Mono>}
      sub={platform(agent)}
      footer={
        <>
          <ButtonLink href={`/enrollment/agents/${encodeURIComponent(agent.id)}`} variant="primary">
            Open full page
          </ButtonLink>
          {canRevoke && agent.trust_state !== "revoked" ? (
            <RevokeAction
              endpoint={`/api/enrollment-agents/${agent.id}/revoke`}
              kind="agent"
              label="Revoke agent"
              subject={agent.name || agent.hostname}
              onRevoked={onRevoked}
            />
          ) : null}
        </>
      }
      record={`Enrolled ${formatEnrollmentDateTime(agent.enrolled_at)}${agent.revoked_at ? ` · revoked ${formatEnrollmentDateTime(agent.revoked_at)}` : ""}`}
    >
      <div className="flex flex-wrap gap-2">
        <StatusBadge tone={trust.tone}>{trust.label}</StatusBadge>
        <StatusBadge tone={checkIn.tone}>{checkIn.label}</StatusBadge>
      </div>
      <p className="m-0">{agent.trust_state_reason ?? trust.detail}</p>
      <DefinitionList
        items={[
          { term: "Hostname", value: <Mono>{agent.hostname}</Mono> },
          { term: "Last check-in", value: lastCheckIn(agent, now) },
          { term: "Version", value: formatAgentVersion(agent.agent_version, "Unknown") },
          { term: "Architecture", value: agent.architecture || "Unknown" },
          {
            term: "Fingerprint",
            value: agent.credential_fingerprint ? <Mono>{agent.credential_fingerprint}</Mono> : "None recorded (enrolled before credentials were tracked)",
          },
          { term: "Credential expires", value: formatEnrollmentDateTime(agent.credential_expires_at, "No expiry configured") },
          { term: "Labels", value: agent.labels.length ? agent.labels.join(", ") : "None" },
          { term: "Agent ID", value: <Mono>{agent.id}</Mono> },
        ]}
      />
    </Drawer>
  );
}

export function EnrollmentAgentsTable({
  agents,
  canRevoke,
  now: nowIso,
  caption = "Agents",
  sortNote,
  total,
}: {
  agents: EnrollmentAgent[];
  canRevoke: boolean;
  now: string;
  caption?: string;
  /** Omit to hide the footer. */
  sortNote?: string;
  total?: number;
}) {
  const drawer = useLayeredDrawer<EnrollmentAgent>();
  const now = new Date(nowIso);

  const columns: Column<EnrollmentAgent>[] = [
    {
      key: "agent",
      header: "Agent",
      cell: (agent) => <PrimaryCell mono title={agent.name || agent.hostname} sub={agent.name && agent.name !== agent.hostname ? agent.hostname : agent.environment ?? undefined} />,
    },
    {
      key: "trust",
      header: "Trust",
      cell: (agent) => {
        const badge = agentTrustBadge(agent.trust_state);
        return <StatusBadge tone={badge.tone}>{badge.label}</StatusBadge>;
      },
    },
    {
      key: "checkin",
      header: "Check-in",
      cell: (agent) => {
        const badge = agentCheckInBadge(agent.status);
        return (
          <span className="grid justify-items-start gap-1">
            <StatusBadge tone={badge.tone}>{badge.label}</StatusBadge>
            <span className="text-xs text-(--muted)">{lastCheckIn(agent, now)}</span>
          </span>
        );
      },
    },
    { key: "platform", header: "System", cell: (agent) => <PrimaryCell title={platform(agent)} sub={agent.architecture || undefined} /> },
    { key: "version", header: "Version", cell: (agent) => formatAgentVersion(agent.agent_version, "Unknown") },
    { key: "enrolled", header: "Enrolled", cell: (agent) => formatEnrollmentDateTime(agent.enrolled_at) },
  ];

  return (
    <ModalLayerProvider onChange={drawer.setLayerOpen}>
      <DataTable
        caption={caption}
        columns={columns}
        rows={agents}
        rowKey={(agent) => agent.id}
        rowLabel={(agent) => `Preview ${agent.name || agent.hostname}`}
        onRowSelect={drawer.open}
        minWidth={960}
        state={
          agents.length === 0 ? (
            <EmptyState icon={Monitor} title="No agents enrolled yet" body="Agents appear here as soon as a device uses an enrollment token or installer." />
          ) : undefined
        }
        footer={sortNote && agents.length > 0 ? <TableFooter shown={agents.length} total={total ?? agents.length} sortNote={sortNote} /> : null}
      />
      {drawer.selected ? (
        <AgentDrawer agent={drawer.selected} canRevoke={canRevoke} now={now} onClose={drawer.close} onRevoked={drawer.forceClose} />
      ) : null}
    </ModalLayerProvider>
  );
}
