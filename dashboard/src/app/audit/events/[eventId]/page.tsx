// SPDX-License-Identifier: AGPL-3.0-only

import { notFound, redirect } from "next/navigation";

import {
  auditDetailRows,
  formatAuditAction,
  formatAuditSequence,
  formatAuditTimestamp,
  type AuditEventRecord,
} from "@/lib/audit-core";
import { getAuditEvent } from "@/lib/audit";
import { getDashboardSession } from "@/lib/dashboard-session";
import { NodelinkApiError } from "@/lib/nodelink-api";

import { PageHeader, PageStack } from "@/components/shell/page-header";
import { ButtonLink } from "@/components/ui/button";
import { DefinitionList } from "@/components/ui/drawer";
import { EmptyState, ErrorState } from "@/components/ui/states";
import { cardClass } from "@/components/ui/stat-tile";

export const dynamic = "force-dynamic";

export default async function AuditEventPage({
  params,
}: {
  params: Promise<{ eventId: string }>;
}) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  const { eventId } = await params;

  let event: AuditEventRecord | null = null;
  let loadFailed = false;
  try {
    event = await getAuditEvent(session.sessionToken, eventId);
  } catch (error) {
    if (error instanceof NodelinkApiError && error.status === 404) notFound();
    loadFailed = true;
  }

  if (loadFailed || event === null) return <PageStack><PageHeader breadcrumb={[{ label: "Compliance" }, { label: "Audit", href: "/audit" }]} title="Audit event" /><ErrorState title="This audit event could not be loaded" body="No record could be read. Retry before drawing a conclusion from its absence" /><ButtonLink href="/audit" variant="secondary">Back to the timeline</ButtonLink></PageStack>;
  const rows = auditDetailRows(event.detail);
  return <PageStack>
    <PageHeader breadcrumb={[{ label: "Compliance" }, { label: "Audit", href: "/audit" }, { label: "Event" }]} title={formatAuditAction(event.action)} description={`Sequence ${formatAuditSequence(event.seq)} · recorded ${formatAuditTimestamp(event.ts)}. This page displays stored fields; it does not independently verify this entry.`} actions={<ButtonLink href="/audit/anchors" variant="secondary">Integrity anchors</ButtonLink>} />
    <div className="grid gap-6 min-[1100px]:grid-cols-[minmax(0,2fr)_minmax(280px,1fr)]">
      <section className={`${cardClass} grid content-start gap-4 p-5`}><h2 className="text-base font-semibold">Recorded detail</h2>{rows.length === 0 ? <EmptyState title="No detail fields" body="See the actor, action, subject and sequence in the recorded fields." /> : <DefinitionList items={rows.map(row => ({ term: row.key, value: <code className="break-all whitespace-pre-wrap">{row.value}</code> }))} />}</section>
      <section className={`${cardClass} grid content-start gap-4 p-5`}><h2 className="text-base font-semibold">At a glance</h2><DefinitionList items={[
        { term: "Event ID", value: <code className="break-all">{event.id}</code> },
        { term: "Sequence", value: formatAuditSequence(event.seq) },
        { term: "Action", value: event.action }, { term: "Actor", value: event.actor },
        { term: "Actor user ID", value: event.actor_user_id ?? "—" }, { term: "Agent", value: event.agent_id ?? "—" },
        { term: "Enrollment token", value: event.enrollment_token_id ?? "—" }, { term: "Organization", value: event.organization_id ?? "—" },
        { term: "Source IP", value: event.source_ip ?? "Not recorded" }, { term: "Recorded", value: formatAuditTimestamp(event.ts) },
      ]} /></section>
    </div>
  </PageStack>;
}
