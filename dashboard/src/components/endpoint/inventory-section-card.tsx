// SPDX-License-Identifier: AGPL-3.0-only

import { ChevronRight } from "lucide-react";
import Link from "next/link";

import { inventoryBadge } from "@/lib/endpoint-pages-core";
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
  type InventorySectionRecord,
  type InventorySectionStatus,
} from "@/lib/inventory-core";

import { DefinitionList } from "../ui/drawer";
import { StatusBadge } from "../ui/status-badge";
import { endpointBase, inlineLink, Panel } from "./section-header";

const LIST_LIMIT = 12;

/** Fixed-vocabulary badge plus the precise section status when it is not plain "collected". */
export function InventoryStatus({ status }: { status: InventorySectionStatus }) {
  const badge = inventoryBadge(status);
  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <StatusBadge tone={badge.tone}>{badge.label}</StatusBadge>
      {status === "ok" ? null : <span className="text-xs text-(--muted)">{statusLabel(status)}</span>}
    </span>
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

const note = "m-0 text-[13px] text-(--muted)";

export function InventorySectionCard({ endpointId, section }: { endpointId: string; section: InventorySectionRecord }) {
  const lag = collectionLagSeconds(section);
  const rows = payloadRows(section.payload);
  const lists = payloadLists(section.payload);
  const label = sectionLabel(section.section);
  return (
    <Panel
      title={label}
      sub={`Collected ${formatInventoryTimestamp(section.collected_at)} · ${formatBytes(section.byte_size)}`}
      action={<InventoryStatus status={section.status} />}
    >
      <div className="grid gap-4 px-5 py-4">
        {section.status === "ok" ? null : <p className={note}>{statusExplanation(section.status)}</p>}
        {hasSuspiciousLag(lag) && lag !== null ? (
          <p className={note}>
            Reported {formatLag(lag)} after it was collected — the endpoint was queued or its clock differs. Treat these values as of the collection time, not now.
          </p>
        ) : null}

        {rows.length === 0 && lists.length === 0 ? <p className={note}>No fields were reported for this section.</p> : null}

        {rows.length > 0 ? <DefinitionList items={rows.map((row) => ({ term: row.key.replaceAll("_", " "), value: row.value }))} /> : null}

        {lists.map((list) => (
          <section key={list.key} aria-label={list.key.replaceAll("_", " ")} className="grid gap-2">
            <h3 className="m-0 flex items-center gap-2 text-[13px] font-semibold text-(--slate)">
              {list.key.replaceAll("_", " ")}
              <span className="rounded-full bg-(--fog) px-2 text-xs text-(--muted)">{list.items.length}</span>
            </h3>
            {list.items.length === 0 ? (
              <p className={note}>None reported.</p>
            ) : (
              <ul className="m-0 grid list-none gap-1 p-0 text-[13px] text-(--slate)">
                {list.items.slice(0, LIST_LIMIT).map((item, index) => (
                  <li key={index} className="border-t border-(--line) pt-1 first:border-t-0 first:pt-0 break-words">
                    {describeListItem(item)}
                  </li>
                ))}
              </ul>
            )}
            {list.items.length > LIST_LIMIT ? (
              <p className={note}>
                Showing {LIST_LIMIT} of {list.items.length}.
              </p>
            ) : null}
          </section>
        ))}

        <Link href={`${endpointBase(endpointId)}/inventory/${encodeURIComponent(section.section)}`} className={`${inlineLink} inline-flex items-center gap-1 text-sm`}>
          History and changes<span className="sr-only">: {label}</span> <ChevronRight size={14} aria-hidden="true" />
        </Link>
      </div>
    </Panel>
  );
}
