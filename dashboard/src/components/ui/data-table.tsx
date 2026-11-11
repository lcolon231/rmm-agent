// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { ChevronRight } from "lucide-react";
import type { KeyboardEvent, ReactNode } from "react";

import { cx, focusRing } from "./cx";
import { cardClass } from "./stat-tile";

export type Column<T> = {
  key: string;
  header: string;
  cell: (row: T) => ReactNode;
  /** Right-align numbers and meters' neighbours where it helps scanning. */
  align?: "start" | "end";
};

type DataTableProps<T> = {
  /** Accessible table name, e.g. "Devices". */
  caption: string;
  columns: readonly Column<T>[];
  rows: readonly T[];
  rowKey: (row: T) => string;
  /** Opens the preview drawer; whole row is clickable and keyboard-focusable. */
  onRowSelect?: (row: T) => void;
  /** Accessible name for the row action, e.g. `Open ${row.hostname}`. */
  rowLabel?: (row: T) => string;
  filters?: ReactNode;
  footer?: ReactNode;
  /** Shown instead of the table body: Skeleton, EmptyState or ErrorState. */
  state?: ReactNode;
  density?: "comfortable" | "compact";
  minWidth?: number;
};

/** First column: 14px / 600 ink with an optional muted second line. */
export function PrimaryCell({ title, sub, mono = false }: { title: ReactNode; sub?: ReactNode; mono?: boolean }) {
  return (
    <span className="grid gap-0.5">
      <span className={cx("font-semibold text-(--ink)", mono && "font-(family-name:--font-data) text-[13px]")}>{title}</span>
      {sub ? <span className="text-xs text-(--muted)">{sub}</span> : null}
    </span>
  );
}

export function DataTable<T>({
  caption,
  columns,
  rows,
  rowKey,
  onRowSelect,
  rowLabel,
  filters,
  footer,
  state,
  density = "comfortable",
  minWidth = 880,
}: DataTableProps<T>) {
  const cellPad = density === "compact" ? "px-5 py-2" : "px-5 py-3.5";

  function onKeyDown(event: KeyboardEvent<HTMLTableRowElement>, row: T) {
    if (event.key !== "Enter" && event.key !== " ") return;
    event.preventDefault();
    onRowSelect?.(row);
  }

  return (
    <section aria-label={caption} className={cx(cardClass, "overflow-hidden")}>
      {filters}
      {state ?? (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left text-sm" style={{ minWidth }}>
            <caption className="sr-only">{caption}</caption>
            <thead className="bg-(--fog)">
              <tr>
                {columns.map((column) => (
                  <th
                    key={column.key}
                    scope="col"
                    className={cx("px-5 py-2.5 text-xs font-semibold whitespace-nowrap text-(--muted)", column.align === "end" && "text-right")}
                  >
                    {column.header}
                  </th>
                ))}
                {onRowSelect ? (
                  <th scope="col" className="w-10 px-5 py-2.5">
                    <span className="sr-only">Open</span>
                  </th>
                ) : null}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr
                  key={rowKey(row)}
                  tabIndex={onRowSelect ? 0 : undefined}
                  aria-label={onRowSelect && rowLabel ? rowLabel(row) : undefined}
                  onClick={onRowSelect ? () => onRowSelect(row) : undefined}
                  onKeyDown={onRowSelect ? (event) => onKeyDown(event, row) : undefined}
                  className={cx("border-t border-(--line) text-(--slate)", onRowSelect && cx("cursor-pointer hover:bg-(--primary-tint)", focusRing, "focus-visible:-outline-offset-2"))}
                >
                  {columns.map((column) => (
                    <td key={column.key} className={cx(cellPad, "align-middle whitespace-nowrap", column.align === "end" && "text-right")}>
                      {column.cell(row)}
                    </td>
                  ))}
                  {onRowSelect ? (
                    <td className={cx(cellPad, "text-(--muted)")}>
                      <ChevronRight size={16} aria-hidden="true" />
                    </td>
                  ) : null}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {footer}
    </section>
  );
}

type TableFooterProps = {
  shown: number;
  total: number;
  /** How the rows are ordered; say "on this page" when the order is not global. */
  sortNote?: string;
  /** Pagination controls (36px icon buttons), usually URL-driven links. */
  pagination?: ReactNode;
};

export function TableFooter({ shown, total, sortNote = "most urgent first", pagination }: TableFooterProps) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t border-(--line) px-5 py-3 text-xs text-(--muted)">
      <p className="m-0">
        Showing {shown} of {total} · {sortNote}
      </p>
      {pagination ? <nav aria-label="Pages" className="flex items-center gap-1">{pagination}</nav> : null}
    </div>
  );
}
