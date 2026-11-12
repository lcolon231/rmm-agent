// SPDX-License-Identifier: AGPL-3.0-only

import { Anchor as AnchorIcon, ShieldCheck, Clock } from "lucide-react";
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

import { PageHeader, PageStack } from "@/components/shell/page-header";
import { StatRow, StatTile, cardClass } from "@/components/ui/stat-tile";
import { TabNav } from "@/components/ui/tab-nav";
import { StatusBadge } from "@/components/ui/status-badge";
import { CodeBlock } from "@/components/ui/drawer";

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
    <PageStack>
      <PageHeader breadcrumb={[{ label: "Compliance" }, { label: "Audit", href: "/audit" }, { label: "Integrity anchors" }]} title="Anchors and publication receipts" description="Review chain anchors and external publication results. Verification is limited to the 25 most recent anchors." />
      <StatRow><StatTile icon={AnchorIcon} label="Anchors loaded" value={anchors?.length ?? "—"} /><StatTile icon={ShieldCheck} label="Verified this load" value={anchors === null ? "—" : [...verifications.values()].filter(value => value?.intact).length} /><StatTile icon={Clock} label="Pending publication" value={publication?.pending ?? "—"} /></StatRow>
      <TabNav label="Audit views" tabs={[{ label: "Events", href: "/audit", current: false }, { label: "Integrity anchors", href: "/audit/anchors", current: true }]} />

      <AuditIntegrityBanner statement={publicationStatement} />

      <section className="grid gap-4">
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
          <div className={`${cardClass} grid gap-2 p-5 text-sm`} role="alert">
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
          <div className="grid gap-4">
            {ordered.map((anchor) => {
              const verified = inspected.includes(anchor);
              const verification = describeAnchorVerification(
                verified ? verifications.get(anchor.id) ?? null : null,
              );
              const receipt = receipts.get(anchor.id) ?? null;
              return (
                <article className={`${cardClass} grid gap-4 p-5`} key={anchor.id}>
                  <header>
                    <div>
                      <strong>{formatAuditTimestamp(anchor.created_at)}</strong>
                      <small>
                        {anchor.event_count} event{anchor.event_count === 1 ? "" : "s"} covered · last{" "}
                        <code>{anchor.last_event_id}</code>
                      </small>
                    </div>
                    <StatusBadge tone={verification.tone === "verified" ? "ok" : verification.tone === "failed" ? "crit" : "off"}>{verification.headline}</StatusBadge>
                  </header>
                  <p className="text-sm text-(--muted)">{verification.detail}</p>
                  <CodeBlock label="Merkle root">{anchor.merkle_root}</CodeBlock>

                  {!verified ? null : receipt === null ? (
                    <p className="text-sm text-(--muted)">Publication receipts could not be read for this anchor.</p>
                  ) : receipt.publications.length === 0 ? (
                    <p className="text-sm text-(--muted)">
                      No external publication has been attempted for this anchor.
                    </p>
                  ) : (
                    <ul className="grid gap-3 text-sm [&_li]:grid [&_li]:gap-2 [&_code]:break-all">
                      {receipt.publications.map((entry) => {
                        const statement = describeReceipt(entry);
                        return (
                          <li key={`${entry.backend}-${entry.uri ?? entry.status}`}>
                            <StatusBadge tone={statement.tone === "verified" ? "ok" : statement.tone === "failed" ? "crit" : "off"}>{statement.headline}</StatusBadge>
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
    </PageStack>
  );
}
