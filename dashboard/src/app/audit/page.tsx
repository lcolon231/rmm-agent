// SPDX-License-Identifier: AGPL-3.0-only

import { ChevronLeft, ChevronRight, Filter, ListChecks, ShieldCheck } from "lucide-react";
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
  formatAuditSequence,
  formatAuditTimestamp,
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

  return (
    <>
      <header className="enrollment-page-head">
        <div>
          <span>Tamper-evident evidence</span>
          <h1>Audit timeline</h1>
          <p>
            Every recorded action in sequence order, newest first. Sequence numbers are the values the
            hash chain binds, so a gap here is a gap in the evidence.
          </p>
        </div>
        <Link className="enrollment-primary-link" href="/audit/anchors">
          <ShieldCheck size={16} /> Anchors &amp; receipts
        </Link>
      </header>

      <AuditIntegrityBanner statement={chainStatement} />
      <AuditIntegrityBanner statement={publicationStatement} />

      <form className="enrollment-filter audit-filter" method="get">
        <label>
          <Filter size={16} />
          <span className="sr-only">Filter event type</span>
          <select defaultValue={query.eventType ?? ""} name="event">
            <option value="">All events</option>
            {eventTypes.map((eventType) => (
              <option key={eventType} value={eventType}>
                {formatAuditAction(eventType)}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="sr-only">Filter by actor</span>
          <input defaultValue={query.actor ?? ""} name="actor" placeholder="Actor contains…" type="search" />
        </label>
        <label>
          <span className="sr-only">Filter by agent ID</span>
          <input defaultValue={query.agentId ?? ""} name="agent" placeholder="Agent ID" type="search" />
        </label>
        <label>
          <span className="sr-only">Events from date (UTC)</span>
          <input defaultValue={query.dateFrom ?? ""} name="from" type="date" />
        </label>
        <label>
          <span className="sr-only">Events to date (UTC)</span>
          <input defaultValue={query.dateTo ?? ""} name="to" type="date" />
        </label>
        <button type="submit">Apply</button>
        {hasAuditFilters(query) ? <Link className="audit-filter-clear" href="/audit">Clear</Link> : null}
      </form>

      <section className="enrollment-panel">
        <header>
          <div>
            <span>Audit register</span>
            <h2>
              {events === null ? "Unavailable" : `${events.total} event${events.total === 1 ? "" : "s"}`}
            </h2>
            {events === null ? null : (
              <small>
                Page {events.page} of {pageCount} · {AUDIT_PAGE_SIZE} per page
                {events.before_seq === null ? "" : ` · through seq ${events.before_seq}`}
              </small>
            )}
          </div>
          <ListChecks size={19} />
        </header>

        {events === null ? (
          <div className="enrollment-empty" role="alert">
            <ListChecks size={24} />
            <h3>The audit timeline could not be loaded</h3>
            <p>
              No events are shown because none could be read — this is not evidence that no events
              exist. Retry, and treat the gap as unexplained until the timeline loads.
            </p>
          </div>
        ) : events.items.length === 0 ? (
          <div className="enrollment-empty">
            <ListChecks size={24} />
            <h3>No events match these filters</h3>
            <p>
              {hasAuditFilters(query)
                ? "Clear or widen the filters to see the surrounding sequence."
                : "No audit events have been recorded yet."}
            </p>
          </div>
        ) : (
          <div className="enrollment-table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Seq</th>
                  <th>Action</th>
                  <th>Actor</th>
                  <th>Subject</th>
                  <th>Source</th>
                  <th>Recorded (UTC)</th>
                </tr>
              </thead>
              <tbody>
                {events.items.map((event) => (
                  <tr key={event.id}>
                    <td><code>{formatAuditSequence(event.seq)}</code></td>
                    <td>
                      <Link href={`/audit/events/${encodeURIComponent(event.id)}`}>
                        {formatAuditAction(event.action)}
                      </Link>
                      <code>{event.id}</code>
                    </td>
                    <td>{event.actor}</td>
                    <td>
                      {event.agent_id ? <code>agent {event.agent_id}</code> : null}
                      {event.enrollment_token_id ? <code>token {event.enrollment_token_id}</code> : null}
                      {!event.agent_id && !event.enrollment_token_id ? "—" : null}
                    </td>
                    <td>{event.source_ip ?? "Not recorded"}</td>
                    <td>{formatAuditTimestamp(event.ts)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {events === null || events.items.length === 0 ? null : (
          <footer className="enrollment-pagination">
            <span>
              Showing {events.items.length} of {events.total} event{events.total === 1 ? "" : "s"}
            </span>
            <span className="audit-pager">
              {query.page > 1 ? (
                <Link href={auditPageHref(query, query.page - 1, events.before_seq)} rel="prev">
                  <ChevronLeft size={14} /> Newer
                </Link>
              ) : null}
              {hasNextAuditPage(events.page, events.total) ? (
                <Link href={auditPageHref(query, query.page + 1, events.before_seq)} rel="next">
                  Older <ChevronRight size={14} />
                </Link>
              ) : null}
            </span>
          </footer>
        )}
      </section>

      {failing ? null : (
        <p className="audit-note">
          Viewing this timeline is itself recorded as an <code>audit_timeline.viewed</code> event, so
          the register grows as it is read. Paging stays pinned to the sequence ceiling shown above —
          {query.beforeSeq ? " you are viewing a snapshot; " : " "}
          {query.beforeSeq ? (
            <Link href="/audit">reload for the newest events</Link>
          ) : (
            "events recorded while you page are picked up on the next fresh load"
          )}
          .
        </p>
      )}
    </>
  );
}
