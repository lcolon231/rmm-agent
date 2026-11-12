// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { History } from "lucide-react";

import { formatInventoryTimestamp, type InventorySectionRecord } from "@/lib/inventory-core";

import { DataTable, TableFooter, type Column } from "../ui/data-table";
import { EmptyState } from "../ui/states";
import { InventoryStatus } from "./inventory-section-card";
import { HistoryPager, monoText } from "./section-header";

type InventoryHistoryTableProps = {
  items: InventorySectionRecord[];
  page: number;
  pageSize: number;
  total: number;
};

/** Stored snapshots of one inventory section, newest first, URL-paged. */
export function InventoryHistoryTable({ items, page, pageSize, total }: InventoryHistoryTableProps) {
  const columns: Column<InventorySectionRecord>[] = [
    { key: "collected", header: "Collected (UTC)", cell: (item) => formatInventoryTimestamp(item.collected_at) },
    { key: "received", header: "Received", cell: (item) => formatInventoryTimestamp(item.received_at) },
    { key: "status", header: "Status", cell: (item) => <InventoryStatus status={item.status} /> },
    {
      key: "hash",
      header: "Fingerprint",
      cell: (item) => (
        <span className={monoText} title={item.content_hash}>
          {item.content_hash.slice(0, 16)}…
        </span>
      ),
    },
  ];
  const hasOlder = page * pageSize < total;

  return (
    <DataTable
      caption="Snapshots"
      columns={columns}
      rows={items}
      rowKey={(item) => item.id}
      minWidth={640}
      filters={
        <header className="grid gap-0.5 border-b border-(--line) px-5 py-4">
          <h2 className="m-0 text-base font-semibold text-(--ink)">Snapshots</h2>
          <p className="m-0 text-xs text-(--muted)">
            History is bounded by retention. The newest snapshot is never pruned, so a device always keeps its current reported state.
          </p>
        </header>
      }
      state={items.length === 0 ? <EmptyState icon={History} title="No snapshots recorded" body="This device has never reported this section." /> : undefined}
      footer={
        items.length ? (
          <TableFooter
            shown={items.length}
            total={total}
            sortNote="newest first"
            pagination={
              total > pageSize ? (
                <HistoryPager
                  page={page}
                  newerHref={page > 1 ? `?page=${page - 1}` : null}
                  olderHref={hasOlder ? `?page=${page + 1}` : null}
                />
              ) : undefined
            }
          />
        ) : null
      }
    />
  );
}
