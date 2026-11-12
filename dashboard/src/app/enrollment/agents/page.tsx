// SPDX-License-Identifier: AGPL-3.0-only

import { Ban, Clock, MonitorCheck, MonitorOff, Plus } from "lucide-react";
import { redirect } from "next/navigation";

import { EnrollmentAgentsTable } from "@/components/enrollment/agents-view";
import { EnrollmentHeader } from "@/components/enrollment/enrollment-header";
import { PageStack } from "@/components/shell/page-header";
import { ButtonLink } from "@/components/ui/button";
import { StatRow, StatTile } from "@/components/ui/stat-tile";
import { countAgents, sortAgentsByAttention } from "@/lib/admin-screens-core";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getEnrollmentAgents } from "@/lib/enrollment";
import { canManageEnrollment } from "@/lib/enrollment-core";

export default async function EnrollmentAgentsPage() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");
  const agents = await getEnrollmentAgents(session.sessionToken);
  const role = session.operator.role;
  const counts = countAgents(agents);

  return (
    <PageStack>
      <EnrollmentHeader
        tab="agents"
        role={role}
        trail={[{ label: "Agents" }]}
        title="Agents"
        description="The NodeLink software on each device, its trust state and when it last checked in."
        actions={
          canManageEnrollment(role) ? (
            <ButtonLink href="/enrollment/installer" variant="primary" icon={Plus}>
              Add a device
            </ButtonLink>
          ) : null
        }
        stats={
          <StatRow>
            <StatTile icon={MonitorCheck} label="Active" tone="ok" value={counts.online} sub="Checking in" />
            <StatTile icon={MonitorOff} label="Offline" tone={counts.offline ? "warn" : "ok"} value={counts.offline} sub="Not checking in" />
            <StatTile icon={Clock} label="Waiting" tone="info" value={counts.waiting} sub="Enrolled, not checked in yet" />
            <StatTile icon={Ban} label="Revoked" tone="off" value={counts.revoked} sub="Can no longer receive commands" />
          </StatRow>
        }
      />
      <EnrollmentAgentsTable
        agents={sortAgentsByAttention(agents)}
        canRevoke={role === "admin"}
        now={new Date().toISOString()}
        sortNote="needing attention first, revoked last"
      />
    </PageStack>
  );
}
