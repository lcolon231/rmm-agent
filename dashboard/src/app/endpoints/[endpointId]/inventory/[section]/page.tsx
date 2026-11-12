// SPDX-License-Identifier: AGPL-3.0-only

import { GitCompareArrows } from "lucide-react";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";

import { InventoryHistoryTable } from "@/components/endpoint/inventory-history-table";
import { EndpointSectionHeader, Notice, PageFailure, Panel } from "@/components/endpoint/section-header";
import { PageStack } from "@/components/shell/page-header";
import {
  describeItem,
  diffIsEmpty,
  formatInventoryTimestamp,
  formatValue,
  sectionLabel,
  totalChanges,
  type InventoryDiffRecord,
} from "@/lib/inventory-core";
import { getInventoryDiff, getInventoryHistory, type InventoryHistoryPage } from "@/lib/inventory";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getEndpointDetail, type EndpointDetailData } from "@/lib/endpoint-detail";
import { NodelinkApiError } from "@/lib/nodelink-api";

export const dynamic = "force-dynamic";

const note = "m-0 text-[13px] text-(--muted)";
const diffLine = "m-0 rounded px-2 py-1 font-(family-name:--font-data) text-[13px] break-words";

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
  let endpoint: EndpointDetailData | null = null;
  try {
    [history, diff] = await Promise.all([
      getInventoryHistory(session.sessionToken, endpointId, section, page),
      // The diff is secondary: a failure here must not blank the history.
      getInventoryDiff(session.sessionToken, endpointId, section).catch(() => null),
      // Only the page header needs the device record; without it the ID stands in.
      getEndpointDetail(session.sessionToken, endpointId, { historyHours: 1, historyLimit: 10 }).catch(() => null),
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
      <PageFailure
        eyebrow="Inventory history"
        title="This section's history could not be loaded"
        body="No snapshots are shown because none could be read. Nothing was changed."
      >
        <Link href={`${backHref}/${encodeURIComponent(section)}`}>Try again</Link>
        <Link href={backHref}>Back to inventory</Link>
      </PageFailure>
    );
  }

  const label = sectionLabel(section);
  const changeCount = diff !== null && diff.comparable ? totalChanges(diff.summary) : 0;

  return (
    <PageStack>
      <EndpointSectionHeader
        endpointId={endpointId}
        hostname={endpointId}
        section="inventory"
        trail={[{ label }]}
        description={`${label}: ${history.total} recorded change${history.total === 1 ? "" : "s"}. A snapshot is stored only when this section's content actually differs, so every row is a real change rather than a routine collection.`}
      />

      <Panel
        title="Most recent change"
        sub={
          diff === null
            ? "Unavailable"
            : !diff.comparable
              ? "Nothing to compare yet"
              : `${changeCount} change${changeCount === 1 ? "" : "s"}`
        }
        action={<GitCompareArrows size={18} aria-hidden="true" className="text-(--muted)" />}
      >
        <div className="grid gap-4 px-5 py-4">
          {diff === null ? (
            <Notice tone="warn" role="alert" title="The comparison could not be computed">
              The history below is unaffected.
            </Notice>
          ) : !diff.comparable ? (
            <p className={note}>There are not enough comparable snapshots to show a change.</p>
          ) : diffIsEmpty(diff.diff) ? (
            <p className={note}>The two most recent snapshots differ in metadata only.</p>
          ) : (
            <>
              <p className={note}>
                {formatInventoryTimestamp(diff.before?.collected_at ?? null)} → {formatInventoryTimestamp(diff.after?.collected_at ?? null)}
              </p>

              {diff.diff.field_changes.length > 0 ? (
                <div className="overflow-x-auto rounded-lg border border-(--line)">
                  <table className="w-full min-w-[480px] border-collapse text-left text-[13px]">
                    <caption className="sr-only">Changed fields</caption>
                    <thead className="bg-(--fog) text-xs text-(--muted)">
                      <tr>
                        <th scope="col" className="px-3 py-2 font-semibold">Field</th>
                        <th scope="col" className="px-3 py-2 font-semibold">Was</th>
                        <th scope="col" className="px-3 py-2 font-semibold">Now</th>
                      </tr>
                    </thead>
                    <tbody>
                      {diff.diff.field_changes.map((change) => (
                        <tr key={change.field} className="border-t border-(--line) text-(--slate)">
                          <td className="px-3 py-2">{change.field.replaceAll("_", " ")}</td>
                          <td className="px-3 py-2 break-words text-(--red)">{formatValue(change.from)}</td>
                          <td className="px-3 py-2 break-words text-(--ink)">{formatValue(change.to)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : null}

              {Object.entries(diff.diff.list_changes).map(([field, change]) => (
                <section key={field} aria-label={field.replaceAll("_", " ")} className="grid gap-1">
                  <h3 className="m-0 text-[13px] font-semibold text-(--slate)">{field.replaceAll("_", " ")}</h3>
                  {change.added.map((item, index) => (
                    <p className={`${diffLine} bg-(--success-soft) text-(--ink)`} key={`add-${index}`}>
                      <span className="sr-only">Added: </span>+ {describeItem(item)}
                    </p>
                  ))}
                  {change.removed.map((item, index) => (
                    <p className={`${diffLine} bg-(--red-soft) text-(--red)`} key={`remove-${index}`}>
                      <span className="sr-only">Removed: </span>− {describeItem(item)}
                    </p>
                  ))}
                  {change.changed.map((item, index) => (
                    <p className={`${diffLine} bg-(--fog) text-(--slate)`} key={`change-${index}`}>
                      <span className="sr-only">Changed: </span>~ {item.identity ? formatValue(item.identity) : "item"} —{" "}
                      {item.changes
                        .map((fieldChange) => `${fieldChange.field}: ${formatValue(fieldChange.from)} → ${formatValue(fieldChange.to)}`)
                        .join("; ")}
                    </p>
                  ))}
                </section>
              ))}
            </>
          )}
        </div>
      </Panel>

      <InventoryHistoryTable items={history.items} page={history.page} pageSize={history.page_size} total={history.total} />
    </PageStack>
  );
}


