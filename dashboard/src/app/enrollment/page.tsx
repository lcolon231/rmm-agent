// SPDX-License-Identifier: AGPL-3.0-only

import { ArrowRight, Ban, KeyRound, MonitorCheck, MonitorOff, Plus } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";

import { StatusNote } from "@/components/admin/admin-ui";
import { EnrollmentAgentsTable } from "@/components/enrollment/agents-view";
import { EnrollmentHeader } from "@/components/enrollment/enrollment-header";
import { PageStack } from "@/components/shell/page-header";
import { ButtonLink } from "@/components/ui/button";
import { StatRow, StatTile } from "@/components/ui/stat-tile";
import { getClientNavigation } from "@/lib/client-navigation";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getEnrollmentDashboard } from "@/lib/enrollment";

export default async function EnrollmentDashboardPage() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");
  const [data, navigation] = await Promise.all([
    getEnrollmentDashboard(session.sessionToken),
    getClientNavigation(session.sessionToken),
  ]);
  const role = session.operator.role;
  const hasSites = navigation.items.some((client) => client.sites.length > 0);
  const canManage = role !== "readonly";

  return (
    <PageStack>
      <EnrollmentHeader
        tab="overview"
        role={role}
        title="Enrollment"
        description="Add devices to NodeLink and keep track of the ones already connected."
        actions={
          canManage ? (
            hasSites ? (
              <ButtonLink href="/enrollment/installer" variant="primary" icon={Plus}>
                Add a device
              </ButtonLink>
            ) : (
              <ButtonLink href="/enrollment/setup" variant="primary" icon={ArrowRight}>
                Start setup
              </ButtonLink>
            )
          ) : null
        }
        stats={
          <StatRow>
            <StatTile icon={MonitorCheck} label="Active agents" tone="ok" value={data.active_agents} sub={`Trusted and not offline · ${data.total_agents} enrolled`} />
            <StatTile icon={MonitorOff} label="Offline agents" tone={data.offline_agents ? "warn" : "ok"} value={data.offline_agents} sub="Not checking in" />
            <StatTile icon={KeyRound} label="Active tokens" tone="info" value={data.active_enrollment_tokens} sub={`${data.expired_tokens} expired`} />
            <StatTile icon={Ban} label="Revoked agents" tone="off" value={data.revoked_agents} sub="Can no longer receive commands" />
          </StatRow>
        }
      />
      {!hasSites && canManage ? (
        <StatusNote
          tone="warn"
          title="Create a client and site first"
          action={
            <ButtonLink href="/enrollment/setup" icon={ArrowRight}>
              Start setup
            </ButtonLink>
          }
        >
          Devices cannot be added until a site exists.
        </StatusNote>
      ) : null}
      {data.recent_enrollment_failures > 0 ? (
        <StatusNote
          tone="warn"
          role="status"
          title={`${data.recent_enrollment_failures} failed enrollment ${data.recent_enrollment_failures === 1 ? "attempt" : "attempts"} in the last 24 hours`}
          action={
            <Link href="/enrollment/audit?event=agent.enrollment_failed" className="font-semibold text-(--primary-strong)">
              Review
            </Link>
          }
        />
      ) : null}
      <div className="grid gap-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="m-0 text-base font-semibold text-(--ink)">Recently enrolled agents</h2>
          <Link href="/enrollment/agents" className="inline-flex items-center gap-1 text-sm font-semibold text-(--primary-strong)">
            All agents <ArrowRight size={14} aria-hidden="true" />
          </Link>
        </div>
        <EnrollmentAgentsTable
          agents={data.recently_enrolled_agents}
          caption="Recently enrolled agents"
          canRevoke={false}
          now={new Date().toISOString()}
        />
      </div>
    </PageStack>
  );
}
