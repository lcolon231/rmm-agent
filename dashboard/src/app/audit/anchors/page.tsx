// SPDX-License-Identifier: AGPL-3.0-only

import { ArrowLeft, Anchor as AnchorIcon } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";

import { AuditIntegrityBanner } from "@/components/audit-integrity-banner";
import {
  describeAnchorVerification,
  describePublication,
  describeReceipt,
  formatAuditTimestamp,
  type AuditAnchorRecord,
  type AuditAnchorVerification,
  type AuditPublicationStatus,
} from "@/lib/audit-core";
import {
  getAuditAnchorReceipts,
  getAuditAnchors,
  getAuditPublicationStatus,
  verifyAuditAnchor,
  type AuditAnchorReceipts,
} from "@/lib/audit";
import { getDashboardSession } from "@/lib/dashboard-session";

export const dynamic = "force-dynamic";

/**
 * Verifying and fetching receipts is O(anchors), so the page verifies a bounded
 * window of the most recent anchors rather than the whole history. Older
 * anchors are still listed; they are simply reported as not verified in this
 * request instead of silently appearing healthy.
 */
const VERIFIED_ANCHOR_LIMIT = 25;

export default async function AuditAnchorsPage() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  const [anchors, publication] = await Promise.all([
    getAuditAnchors(session.sessionToken).catch((): AuditAnchorRecord[] | null => null),
    getAuditPublicationStatus(session.sessionToken).catch((): AuditPublicationStatus | null => null),
  ]);

  const ordered = [...(anchors ?? [])].reverse();
  const inspected = ordered.slice(0, VERIFIED_ANCHOR_LIMIT);

  const verifications = new Map<string, AuditAnchorVerification | null>();
  const receipts = new Map<string, AuditAnchorReceipts | null>();
  await Promise.all(
    inspected.map(async (anchor) => {
      const [verification, receipt] = await Promise.all([
        verifyAuditAnchor(session.sessionToken, anchor.id).catch(() => null),
        getAuditAnchorReceipts(session.sessionToken, anchor.id).catch(() => null),
      ]);
      verifications.set(anchor.id, verification);
      receipts.set(anchor.id, receipt);
    }),
  );

  const publicationStatement = describePublication(publication);

  return (
    <>
      <header className="enrollment-page-head compact">
        <div>
          <span>External verification</span>
          <h1>Anchors and publication receipts</h1>
          <p>
            An anchor commits to the whole chain up to a point. Its value only becomes un-rewritable
            once a copy exists outside this database, which is what a publication receipt proves.
          </p>
        </div>
        <Link className="enrollment-primary-link" href="/audit">
          <ArrowLeft size={16} /> Timeline
        </Link>
      </header>

      <AuditIntegrityBanner statement={publicationStatement} />

      <section className="enrollment-panel">
        <header>
          <div>
            <span>Merkle anchors</span>
            <h2>{anchors === null ? "Unavailable" : `${anchors.length} anchor${anchors.length === 1 ? "" : "s"}`}</h2>
            {anchors !== null && ordered.length > inspected.length ? (
              <small>Verifying the {VERIFIED_ANCHOR_LIMIT} most recent</small>
            ) : null}
          </div>
          <AnchorIcon size={19} />
        </header>

        {anchors === null ? (
          <div className="enrollment-empty" role="alert">
            <AnchorIcon size={24} />
            <h3>Anchors could not be loaded</h3>
            <p>No anchors are shown because none could be read. This is not evidence that none exist.</p>
          </div>
        ) : ordered.length === 0 ? (
          <div className="enrollment-empty">
            <AnchorIcon size={24} />
            <h3>No anchors have been created</h3>
            <p>
              Until an anchor exists and is published externally, the chain is only self-consistent —
              it cannot survive an attacker who controls this database.
            </p>
          </div>
        ) : (
          <div className="audit-anchor-list">
            {ordered.map((anchor) => {
              const verified = inspected.includes(anchor);
              const verification = describeAnchorVerification(
                verified ? verifications.get(anchor.id) ?? null : null,
              );
              const receipt = receipts.get(anchor.id) ?? null;
              return (
                <article className="audit-anchor" key={anchor.id}>
                  <header>
                    <div>
                      <strong>{formatAuditTimestamp(anchor.created_at)}</strong>
                      <small>
                        {anchor.event_count} event{anchor.event_count === 1 ? "" : "s"} covered · last{" "}
                        <code>{anchor.last_event_id}</code>
                      </small>
                    </div>
                    <span className={`audit-tone ${verification.tone}`}>{verification.headline}</span>
                  </header>
                  <p className="audit-anchor-reason">{verification.detail}</p>
                  <div className="audit-root">
                    <span>Merkle root</span>
                    <code>{anchor.merkle_root}</code>
                  </div>

                  {!verified ? null : receipt === null ? (
                    <p className="audit-anchor-reason">Publication receipts could not be read for this anchor.</p>
                  ) : receipt.publications.length === 0 ? (
                    <p className="audit-anchor-reason">
                      No external publication has been attempted for this anchor.
                    </p>
                  ) : (
                    <ul className="audit-receipts">
                      {receipt.publications.map((entry) => {
                        const statement = describeReceipt(entry);
                        return (
                          <li key={`${entry.backend}-${entry.uri ?? entry.status}`}>
                            <span className={`audit-tone ${statement.tone}`}>{statement.headline}</span>
                            <span>{statement.detail}</span>
                            {entry.receipt_sha256 ? <code>{entry.receipt_sha256}</code> : null}
                            <small>
                              {entry.published_at
                                ? `Published ${formatAuditTimestamp(entry.published_at)}`
                                : "Not published"}
                            </small>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                </article>
              );
            })}
          </div>
        )}
      </section>
    </>
  );
}
