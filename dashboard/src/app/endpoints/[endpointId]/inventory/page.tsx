// SPDX-License-Identifier: AGPL-3.0-only

import { AlertTriangle, ArrowLeft, ChevronRight, HardDrive } from "lucide-react";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";

import { WindowsUpdateInstallation } from "@/components/windows-update-installation";
import {
  collectionLagSeconds,
  formatBytes,
  formatInventoryTimestamp,
  formatLag,
  hasSuspiciousLag,
  payloadLists,
  payloadRows,
  sectionLabel,
  statusExplanation,
  statusLabel,
  statusTone,
  type InventoryRecord,
} from "@/lib/inventory-core";
import { getEndpointInventory } from "@/lib/inventory";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getEndpointDetail, type EndpointDetailData } from "@/lib/endpoint-detail";
import { NodelinkApiError } from "@/lib/nodelink-api";
import {
  windowsUpdateScanIsStale,
  windowsUpdatesFromUnknown,
} from "@/lib/windows-updates-core";

export const dynamic = "force-dynamic";

export default async function EndpointInventoryPage({
  params,
}: {
  params: Promise<{ endpointId: string }>;
}) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  const { endpointId } = await params;

  let inventory: InventoryRecord | null = null;
  let endpoint: EndpointDetailData | null = null;
  let loadFailed = false;
  try {
    [inventory, endpoint] = await Promise.all([
      getEndpointInventory(session.sessionToken, endpointId),
      getEndpointDetail(session.sessionToken, endpointId, { historyHours: 1, historyLimit: 1 }),
    ]);
  } catch (error) {
    if (error instanceof NodelinkApiError && error.status === 404) notFound();
    loadFailed = true;
  }

  if (loadFailed || inventory === null || endpoint === null) {
    return (
      <main className="detail-failure-page">
        <section role="alert">
          <span>Inventory</span>
          <h1>Inventory is temporarily unavailable</h1>
          <p>
            No sections are shown because none could be read. This is not evidence that the
            endpoint has reported nothing.
          </p>
          <Link href={`/endpoints/${encodeURIComponent(endpointId)}`}>Back to endpoint</Link>
        </section>
      </main>
    );
  }

  // A section that could not be collected must not sit quietly beside a healthy
  // one — an unread BitLocker state is the case this page exists to surface.
  const attention = inventory.sections.filter(
    (section) => statusTone(section.status) === "failed",
  );
  // This server-only request timestamp is serialized into the client component
  // as a boolean, so hydration never recomputes or disagrees about freshness.
  // eslint-disable-next-line react-hooks/purity
  const renderedAt = Date.now();

  return (
    <main className="workspace section-workspace">
      <div className="content-column">
        <header className="enrollment-page-head">
          <div>
            <span>Endpoint inventory</span>
            <h1>Collected state</h1>
            <p>
              What this endpoint reported, when it reported it, and how completely. Sections are
              stored only when their content changes, so each timestamp is the last time the value
              actually differed.
            </p>
          </div>
          <Link
            className="enrollment-primary-link"
            href={`/endpoints/${encodeURIComponent(endpointId)}`}
          >
            <ArrowLeft size={16} /> Endpoint
          </Link>
        </header>

        {attention.length > 0 ? (
          <div className="audit-banner failed" role="alert">
            <AlertTriangle aria-hidden="true" size={20} />
            <div>
              <strong>
                {attention.length} section{attention.length === 1 ? "" : "s"} could not be read
              </strong>
              <span>
                {attention.map((section) => sectionLabel(section.section)).join(", ")}. Absence of
                data here means nobody looked — not that nothing is configured.
              </span>
            </div>
          </div>
        ) : null}

        {inventory.sections.length === 0 ? (
          <section className="enrollment-empty">
            <HardDrive size={24} />
            <h2>This endpoint has not reported inventory yet</h2>
            <p>
              A newly enrolled agent reports on its next check-in. Nothing is missing until it has
              had one.
            </p>
          </section>
        ) : (
          <div className="inventory-grid">
            {inventory.sections.map((section) => {
              if (section.section === "windows_updates") {
                const view = windowsUpdatesFromUnknown(section.payload);
                if (view) {
                  return (
                    <WindowsUpdateInstallation
                      canDispatch={session.operator.role === "operator" || session.operator.role === "admin"}
                      endpointId={endpointId}
                      hostname={endpoint.hostname}
                      isStale={windowsUpdateScanIsStale(view.scanned_at, renderedAt)}
                      key={section.id}
                      sectionStatus={section.status}
                      trusted={endpoint.trust_state === "active"}
                      view={view}
                    />
                  );
                }
              }
              const tone = statusTone(section.status);
              const lag = collectionLagSeconds(section);
              const rows = payloadRows(section.payload);
              const lists = payloadLists(section.payload);
              return (
                <section className="enrollment-panel inventory-card" key={section.id}>
                  <header>
                    <div>
                      <span>{sectionLabel(section.section)}</span>
                      <h2>
                        <Link
                          href={`/endpoints/${encodeURIComponent(endpointId)}/inventory/${encodeURIComponent(section.section)}`}
                        >
                          History &amp; changes <ChevronRight size={14} />
                        </Link>
                      </h2>
                      <small>
                        Collected {formatInventoryTimestamp(section.collected_at)} ·{" "}
                        {formatBytes(section.byte_size)}
                      </small>
                    </div>
                    <span className={`audit-tone ${tone}`}>{statusLabel(section.status)}</span>
                  </header>

                  {section.status === "ok" ? null : (
                    <p className="inventory-status-note">{statusExplanation(section.status)}</p>
                  )}
                  {hasSuspiciousLag(lag) && lag !== null ? (
                    <p className="inventory-status-note">
                      Reported {formatLag(lag)} after it was collected — the endpoint was queued or
                      its clock differs. Treat these values as of the collection time, not now.
                    </p>
                  ) : null}

                  {rows.length === 0 && lists.length === 0 ? (
                    <p className="inventory-status-note">No fields were reported for this section.</p>
                  ) : null}

                  {rows.length > 0 ? (
                    <dl className="audit-fields">
                      {rows.map((row) => (
                        <div key={row.key}>
                          <dt>{row.key.replaceAll("_", " ")}</dt>
                          <dd>{row.value}</dd>
                        </div>
                      ))}
                    </dl>
                  ) : null}

                  {lists.map((list) => (
                    <div className="inventory-list" key={list.key}>
                      <h3>
                        {list.key.replaceAll("_", " ")} <span>{list.items.length}</span>
                      </h3>
                      {list.items.length === 0 ? (
                        <p className="inventory-status-note">None reported.</p>
                      ) : (
                        <ul>
                          {list.items.slice(0, 12).map((item, index) => (
                            <li key={index}>{describeListItem(item)}</li>
                          ))}
                        </ul>
                      )}
                      {list.items.length > 12 ? (
                        <p className="inventory-status-note">
                          Showing 12 of {list.items.length}.
                        </p>
                      ) : null}
                    </div>
                  ))}
                </section>
              );
            })}
          </div>
        )}

        {inventory.missing_sections.length > 0 ? (
          <section className="enrollment-panel">
            <header>
              <div>
                <span>Never reported</span>
                <h2>{inventory.missing_sections.length} section
                  {inventory.missing_sections.length === 1 ? "" : "s"}</h2>
              </div>
            </header>
            <p className="inventory-status-note">
              {inventory.missing_sections.map(sectionLabel).join(", ")}. These are named rather than
              hidden so a gap in coverage is visible instead of looking like the section does not
              exist.
            </p>
          </section>
        ) : null}
      </div>
    </main>
  );
}

function describeListItem(item: unknown): string {
  if (item === null || typeof item !== "object") return String(item);
  const record = item as Record<string, unknown>;
  const parts = Object.entries(record)
    .filter(([, value]) => value !== null && value !== undefined && value !== "")
    .slice(0, 4)
    .map(([key, value]) => `${key.replaceAll("_", " ")}: ${String(value)}`);
  return parts.join(" · ");
}
