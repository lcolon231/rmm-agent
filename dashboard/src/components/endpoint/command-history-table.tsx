// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { TerminalSquare } from "lucide-react";
import Link from "next/link";

import { commandDetailRequiresAdmin, commandKindDefinitions, commandPageCount, type CommandHistoryData, type CommandHistoryItem } from "@/lib/command-console-core";
import { formatEndpointDateTime } from "@/lib/endpoint-detail-core";
import { commandBadge } from "@/lib/endpoint-summary-core";

import { DataTable, PrimaryCell, TableFooter, type Column } from "../ui/data-table";
import { EmptyState } from "../ui/states";
import { StatusBadge } from "../ui/status-badge";
import { endpointBase, HistoryPager, inlineLink, monoText } from "./section-header";

export function commandKindLabel(kind: string) {
  return commandKindDefinitions.find((definition) => definition.kind === kind)?.label ?? kind;
}

/** Newest-first command history for one device; each row links to its record. */
export function CommandHistoryTable({ endpointId, history, isAdmin }: { endpointId: string; history: CommandHistoryData; isAdmin: boolean }) {
  const base = `${endpointBase(endpointId)}/commands`;
  const pages = commandPageCount(history.total, history.page_size);

  const columns: Column<CommandHistoryItem>[] = [
    {
      key: "command",
      header: "Command",
      cell: (item) => (
        <PrimaryCell
          title={
            commandDetailRequiresAdmin(item.kind) && !isAdmin ? (
              <span title="Administrator access is required for remediation payloads and results.">{commandKindLabel(item.kind)}</span>
            ) : (
              <Link href={`${base}/${encodeURIComponent(item.id)}`} className={inlineLink}>
                {commandKindLabel(item.kind)}
              </Link>
            )
          }
          sub={<span className={monoText}>{item.id.slice(0, 8)}</span>}
        />
      ),
    },
    {
      key: "status",
      header: "Status",
      cell: (item) => {
        const badge = commandBadge(item.status);
        return <StatusBadge tone={badge.tone}>{badge.label}</StatusBadge>;
      },
    },
    { key: "exit", header: "Exit code", align: "end", cell: (item) => (item.exit_code === null ? "—" : <span className={monoText}>{item.exit_code}</span>) },
    { key: "capture", header: "Output", cell: (item) => (item.stdout_truncated === true || item.stderr_truncated === true ? "Truncated" : "") },
    { key: "sent", header: "Created", cell: (item) => formatEndpointDateTime(item.created_at) },
    { key: "completed", header: "Completed", cell: (item) => formatEndpointDateTime(item.completed_at) },
  ];

  return (
    <DataTable
      caption="Command history"
      columns={columns}
      rows={history.items}
      rowKey={(item) => item.id}
      minWidth={760}
      filters={
        <header className="grid gap-0.5 border-b border-(--line) px-5 py-4">
          <h2 className="m-0 text-base font-semibold text-(--ink)">Command history</h2>
          <p className="m-0 text-xs text-(--muted)">Open a command for its signed record and captured output.</p>
        </header>
      }
      state={
        history.items.length === 0 ? (
          <EmptyState icon={TerminalSquare} title="No commands yet" body="Commands sent to this device will appear here with their full signed record." />
        ) : undefined
      }
      footer={
        history.items.length ? (
          <TableFooter
            shown={history.items.length}
            total={history.total}
            sortNote="newest first"
            pagination={
              pages > 1 ? (
                <HistoryPager
                  page={history.page}
                  pages={pages}
                  newerHref={history.page > 1 ? `${base}?page=${history.page - 1}` : null}
                  olderHref={history.page < pages ? `${base}?page=${history.page + 1}` : null}
                />
              ) : undefined
            }
          />
        ) : null
      }
    />
  );
}
