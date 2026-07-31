// SPDX-License-Identifier: AGPL-3.0-only

import { ArrowLeft, GitCompareArrows, History } from "lucide-react";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";

import {
  describeItem,
  diffIsEmpty,
  formatInventoryTimestamp,
  formatValue,
  sectionLabel,
  statusLabel,
  statusTone,
  totalChanges,
  type InventoryDiffRecord,
} from "@/lib/inventory-core";
import { getInventoryDiff, getInventoryHistory, type InventoryHistoryPage } from "@/lib/inventory";
import { getDashboardSession } from "@/lib/dashboard-session";
import { NodelinkApiError } from "@/lib/nodelink-api";

export const dynamic = "force-dynamic";

export default async function InventorySectionPage({
  params,
  searchParams,
}: {
  params: Promise<{ endpointId: string; section: string }>;
  searchParams: Promise<{ page?: string }>;
}) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  const { endpointId, section } = await params;
  const query = await searchParams;
  const page = /^\d+$/.test(query.page ?? "") ? Math.max(1, Number(query.page)) : 1;

  let history: InventoryHistoryPage | null = null;
  let diff: InventoryDiffRecord | null = null;
  try {
    [history, diff] = await Promise.all([
      getInventoryHistory(session.sessionToken, endpointId, section, page),
      // The diff is secondary: a failure here must not blank the history.
      getInventoryDiff(session.sessionToken, endpointId, section).catch(() => null),
    ]);
  } catch (error) {
    if (error instanceof NodelinkApiError && (error.status === 404 || error.status === 422)) {
      notFound();
    }
    history = null;
  }

  const backHref = `/endpoints/${encodeURIComponent(endpointId)}/inventory`;

  if (history === null) {
    return (
      <main className="detail-failure-page">
        <section role="alert">
          <span>Inventory history</span>
          <h1>This section&rsquo;s history could not be loaded</h1>
          <p>No snapshots are shown because none could be read.</p>
          <Link href={backHref}>Back to inventory</Link>
        </section>
      </main>
    );
  }

  return (
    <main className="workspace section-workspace">
      <div className="content-column">
        <header className="enrollment-page-head compact">
          <div>
            <span>{sectionLabel(section)}</span>
            <h1>Change history</h1>
            <p>
              {history.total} recorded change{history.total === 1 ? "" : "s"}. A snapshot is stored
              only when this section&rsquo;s content actually differs, so every row here is a real
              change rather than a routine collection.
            </p>
          </div>
          <Link className="enrollment-primary-link" href={backHref}>
            <ArrowLeft size={16} /> Inventory
          </Link>
        </header>

        <section className="enrollment-panel">
          <header>
            <div>
              <span>Most recent change</span>
              <h2>
                {diff === null
                  ? "Unavailable"
                  : !diff.comparable
                    ? "Nothing to compare yet"
                    : `${totalChanges(diff.summary)} change${totalChanges(diff.summary) === 1 ? "" : "s"}`}
              </h2>
            </div>
            <GitCompareArrows size={19} />
          </header>

          {diff === null ? (
            <p className="inventory-status-note" role="alert">
              The comparison could not be computed. The history below is unaffected.
            </p>
          ) : !diff.comparable ? (
            <p className="inventory-status-note">
              This endpoint has reported this section once and it has not changed since. That is a
              normal state, not a gap.
            </p>
          ) : diffIsEmpty(diff.diff) ? (
            <p className="inventory-status-note">
              The two most recent snapshots differ in metadata only.
            </p>
          ) : (
            <div className="inventory-diff">
              <p className="inventory-status-note">
                {formatInventoryTimestamp(diff.before?.collected_at ?? null)} →{" "}
                {formatInventoryTimestamp(diff.after?.collected_at ?? null)}
              </p>

              {diff.diff.field_changes.length > 0 ? (
                <table className="inventory-diff-table">
                  <thead>
                    <tr>
                      <th>Field</th>
                      <th>Was</th>
                      <th>Now</th>
                    </tr>
                  </thead>
                  <tbody>
                    {diff.diff.field_changes.map((change) => (
                      <tr key={change.field}>
                        <td>{change.field.replaceAll("_", " ")}</td>
                        <td className="diff-removed">{formatValue(change.from)}</td>
                        <td className="diff-added">{formatValue(change.to)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : null}

              {Object.entries(diff.diff.list_changes).map(([field, change]) => (
                <div className="inventory-diff-list" key={field}>
                  <h3>{field.replaceAll("_", " ")}</h3>
                  {change.added.map((item, index) => (
                    <p className="diff-line diff-added" key={`add-${index}`}>
                      + {describeItem(item)}
                    </p>
                  ))}
                  {change.removed.map((item, index) => (
                    <p className="diff-line diff-removed" key={`remove-${index}`}>
                      − {describeItem(item)}
                    </p>
                  ))}
                  {change.changed.map((item, index) => (
                    <p className="diff-line diff-changed" key={`change-${index}`}>
                      ~ {item.identity ? formatValue(item.identity) : "item"} —{" "}
                      {item.changes
                        .map(
                          (field_change) =>
                            `${field_change.field}: ${formatValue(field_change.from)} → ${formatValue(field_change.to)}`,
                        )
                        .join("; ")}
                    </p>
                  ))}
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="enrollment-panel">
          <header>
            <div>
              <span>Snapshots</span>
              <h2>Newest first</h2>
            </div>
            <History size={19} />
          </header>
          {history.items.length === 0 ? (
            <div className="enrollment-empty">
              <History size={24} />
              <h3>No snapshots recorded</h3>
              <p>This endpoint has never reported this section.</p>
            </div>
          ) : (
            <div className="enrollment-table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Collected (UTC)</th>
                    <th>Received</th>
                    <th>Status</th>
                    <th>Content hash</th>
                  </tr>
                </thead>
                <tbody>
                  {history.items.map((item) => (
                    <tr key={item.id}>
                      <td>{formatInventoryTimestamp(item.collected_at)}</td>
                      <td>{formatInventoryTimestamp(item.received_at)}</td>
                      <td>
                        <span className={`audit-tone ${statusTone(item.status)}`}>
                          {statusLabel(item.status)}
                        </span>
                      </td>
                      <td>
                        <code>{item.content_hash.slice(0, 16)}…</code>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {history.total > history.page_size ? (
            <footer className="enrollment-pagination">
              <span>
                Page {history.page} · {history.total} snapshot
                {history.total === 1 ? "" : "s"}
              </span>
              <span className="audit-pager">
                {page > 1 ? (
                  <Link href={`?page=${page - 1}`} rel="prev">
                    Newer
                  </Link>
                ) : null}
                {history.page * history.page_size < history.total ? (
                  <Link href={`?page=${page + 1}`} rel="next">
                    Older
                  </Link>
                ) : null}
              </span>
            </footer>
          ) : null}
          <p className="inventory-status-note">
            History is bounded by retention. The newest snapshot is never pruned, so an endpoint
            always keeps its current reported state.
          </p>
        </section>
      </div>
    </main>
  );
}
