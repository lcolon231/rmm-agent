// SPDX-License-Identifier: AGPL-3.0-only

import { ChevronLeft, ChevronRight, ListChecks, ShieldCheck, Anchor } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";

import { AuditIntegrityBanner } from "@/components/audit-integrity-banner";
import {
  AUDIT_PAGE_SIZE,
  auditPageCount,
  auditPageHref,
  describeChainIntegrity,
  describePublication,
  formatAuditAction,
  hasAuditFilters,
  hasIntegrityFailure,
  hasNextAuditPage,
  parseAuditQuery,
  type AuditChainVerification,
  type AuditPublicationStatus,
} from "@/lib/audit-core";
import {
  getAuditEventPage,
  getAuditEventTypes,
  getAuditPublicationStatus,
  verifyAuditChain,
  type AuditEventPage,
} from "@/lib/audit";
import { getDashboardSession } from "@/lib/dashboard-session";

import { PageHeader, PageStack } from "@/components/shell/page-header";
import { StatRow, StatTile } from "@/components/ui/stat-tile";
import { TabNav } from "@/components/ui/tab-nav";
import { Button, ButtonLink } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/field";
import { EmptyState, ErrorState } from "@/components/ui/states";
import { TableFooter } from "@/components/ui/data-table";
import { AuditEventsTable } from "@/components/compliance/audit-events-table";

export const dynamic = "force-dynamic";

type SearchParams = {
  actor?: string;
  agent?: string;
  before?: string;
  event?: string;
  from?: string;
  organization?: string;
  page?: string;
  to?: string;
};

export default async function AuditTimelinePage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  const params = await searchParams;

  // The registry drives the filter list, so a filter can never name an action
  // the server would not match. If it cannot be loaded the select degrades to
  // "all events" rather than offering a stale hardcoded list.
  let eventTypes: string[] = [];
  try {
    eventTypes = await getAuditEventTypes(session.sessionToken);
  } catch {
    eventTypes = [];
  }

  const query = parseAuditQuery(params, eventTypes);

  // Each of these is degraded independently: an unavailable verification must
  // not blank the timeline, and an unavailable timeline must not hide a failed
  // verification.
  const [events, chain, publication] = await Promise.all([
    getAuditEventPage(session.sessionToken, query).catch((): AuditEventPage | null => null),
    verifyAuditChain(session.sessionToken).catch((): AuditChainVerification | null => null),
    getAuditPublicationStatus(session.sessionToken).catch((): AuditPublicationStatus | null => null),
  ]);

  const chainStatement = describeChainIntegrity(chain);
  const publicationStatement = describePublication(publication);
  const failing = hasIntegrityFailure(chainStatement, publicationStatement);
  const pageCount = auditPageCount(events?.total ?? 0);

  return <PageStack>
    <PageHeader breadcrumb={[{ label: "Compliance" }, { label: "Audit" }]} title="Audit timeline" description="Recorded actions in sequence order, newest first. Filters may hide intervening events." />
    <StatRow>
      <StatTile icon={ListChecks} label="Matching events" value={events?.total ?? "—"} />
      <StatTile icon={ListChecks} label="Page" value={events ? `${events.page} of ${pageCount}` : "—"} sub={`${AUDIT_PAGE_SIZE} events per page`} />
      <StatTile icon={ShieldCheck} label="Chain check" value={chain === null ? "Unknown" : chain.intact ? "Verified" : "Failed"} tone={chain === null ? "off" : chain.intact ? "ok" : "crit"} />
      <StatTile icon={Anchor} label="Published anchors" value={publication?.published ?? "—"} />
    </StatRow>
    <TabNav label="Audit views" tabs={[{ label: "Events", href: "/audit", current: true }, { label: "Integrity anchors", href: "/audit/anchors", current: false }]} />
    <AuditIntegrityBanner statement={chainStatement} /><AuditIntegrityBanner statement={publicationStatement} />
    <AuditEventsTable rows={events?.items ?? []} filters={<form method="get" className="flex flex-wrap items-end gap-3 border-b border-(--line) p-5">
      <Select label="Event type" name="event" defaultValue={query.eventType ?? ""}><option value="">All events</option>{eventTypes.map(type => <option key={type} value={type}>{formatAuditAction(type)}</option>)}</Select>
      <Input label="Actor" name="actor" type="search" defaultValue={query.actor ?? ""} />
      <Input label="Agent ID" name="agent" type="search" defaultValue={query.agentId ?? ""} />
      <Input label="From date (UTC)" name="from" type="date" defaultValue={query.dateFrom ?? ""} />
      <Input label="To date (UTC)" name="to" type="date" defaultValue={query.dateTo ?? ""} />
      <Button type="submit">Apply</Button>{hasAuditFilters(query) ? <ButtonLink href="/audit" variant="quiet">Clear</ButtonLink> : null}
    </form>}
      state={events === null ? <ErrorState title="The audit timeline could not be loaded" body="No events could be read. This is not evidence that no events exist" /> : events.items.length === 0 ? <EmptyState title="No events match these filters" body={hasAuditFilters(query) ? "Clear or widen the filters to see the surrounding sequence." : "No audit events were returned."} /> : undefined}
      footer={events && events.items.length > 0 ? <TableFooter shown={events.items.length} total={events.total} sortNote={`newest sequence first${events.before_seq === null ? "" : ` · through seq ${events.before_seq}`}`} pagination={<div className="flex gap-3">{query.page > 1 ? <Link href={auditPageHref(query, query.page - 1, events.before_seq)} rel="prev"><ChevronLeft size={14} /> Newer</Link> : null}{hasNextAuditPage(events.page, events.total) ? <Link href={auditPageHref(query, query.page + 1, events.before_seq)} rel="next">Older <ChevronRight size={14} /></Link> : null}</div>} /> : null}
    />
    {failing ? null : <p className="text-xs text-(--muted)">Viewing this timeline is recorded as an <code>audit_timeline.viewed</code> event. Paging stays pinned to the sequence ceiling shown above. {query.beforeSeq ? <Link href="/audit">Reload for the newest events.</Link> : "Events recorded while you page appear on the next fresh load."}</p>}
  </PageStack>;
}
