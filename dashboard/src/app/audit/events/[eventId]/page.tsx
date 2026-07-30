// SPDX-License-Identifier: AGPL-3.0-only

import { ArrowLeft, FileClock } from "lucide-react";
import Link from "next/link";
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

  if (loadFailed || event === null) {
    return (
      <section className="enrollment-empty" role="alert">
        <FileClock size={24} />
        <h1>This audit event could not be loaded</h1>
        <p>No record is shown because none could be read. Retry before drawing any conclusion from its absence.</p>
        <Link href="/audit">Back to the timeline</Link>
      </section>
    );
  }

  const rows = auditDetailRows(event.detail);

  return (
    <>
      <header className="enrollment-page-head compact">
        <div>
          <span>Audit event</span>
          <h1>{formatAuditAction(event.action)}</h1>
          <p>
            Sequence {formatAuditSequence(event.seq)} · recorded {formatAuditTimestamp(event.ts)}. Detail
            fields were sanitized by the redaction policy before they were hashed, so these are the exact
            values chain and anchor verification cover.
          </p>
        </div>
        <Link className="enrollment-primary-link" href="/audit">
          <ArrowLeft size={16} /> Timeline
        </Link>
      </header>

      <section className="enrollment-panel">
        <header><div><span>Identity</span><h2>Recorded fields</h2></div></header>
        <dl className="audit-fields">
          <div><dt>Event ID</dt><dd><code>{event.id}</code></dd></div>
          <div><dt>Sequence</dt><dd><code>{formatAuditSequence(event.seq)}</code></dd></div>
          <div><dt>Action</dt><dd><code>{event.action}</code></dd></div>
          <div><dt>Actor</dt><dd>{event.actor}</dd></div>
          <div><dt>Actor user ID</dt><dd>{event.actor_user_id ? <code>{event.actor_user_id}</code> : "—"}</dd></div>
          <div><dt>Agent</dt><dd>{event.agent_id ? <code>{event.agent_id}</code> : "—"}</dd></div>
          <div><dt>Enrollment token</dt><dd>{event.enrollment_token_id ? <code>{event.enrollment_token_id}</code> : "—"}</dd></div>
          <div><dt>Organization</dt><dd>{event.organization_id ? <code>{event.organization_id}</code> : "—"}</dd></div>
          <div><dt>Source IP</dt><dd>{event.source_ip ?? "Not recorded"}</dd></div>
          <div><dt>Recorded</dt><dd>{formatAuditTimestamp(event.ts)}</dd></div>
        </dl>
      </section>

      <section className="enrollment-panel">
        <header>
          <div><span>Sanitized detail</span><h2>{rows.length} field{rows.length === 1 ? "" : "s"}</h2></div>
          <FileClock size={19} />
        </header>
        {rows.length === 0 ? (
          <div className="enrollment-empty">
            <FileClock size={24} />
            <h3>This action records no detail fields</h3>
            <p>Its accountability evidence is the actor, action, subject, and sequence position above.</p>
          </div>
        ) : (
          <dl className="audit-fields">
            {rows.map((row) => (
              <div key={row.key}>
                <dt>{row.key}</dt>
                <dd><code>{row.value}</code></dd>
              </div>
            ))}
          </dl>
        )}
      </section>
    </>
  );
}
