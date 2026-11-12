// SPDX-License-Identifier: AGPL-3.0-only
"use client";
import Link from "next/link";
import type { ReactNode } from "react";
import { DataTable, PrimaryCell, type Column } from "../ui/data-table";
import { formatAuditAction, formatAuditSequence, formatAuditTimestamp, type AuditEventRecord } from "@/lib/audit-core";
const columns: Column<AuditEventRecord>[] = [
  { key: "seq", header: "Sequence", cell: row => <code>{formatAuditSequence(row.seq)}</code> },
  { key: "action", header: "Action", cell: row => <PrimaryCell title={<Link href={`/audit/events/${encodeURIComponent(row.id)}`}>{formatAuditAction(row.action)}</Link>} sub={row.id} /> },
  { key: "actor", header: "Actor", cell: row => <code>{row.actor}</code> },
  { key: "subject", header: "Subject", cell: row => <span className="grid gap-1"><code>{row.agent_id ?? ""}</code><code>{row.enrollment_token_id ?? ""}</code>{!row.agent_id && !row.enrollment_token_id ? "—" : null}</span> },
  { key: "source", header: "Source", cell: row => row.source_ip ?? "Not recorded" },
  { key: "time", header: "Recorded (UTC)", cell: row => formatAuditTimestamp(row.ts) },
];
export function AuditEventsTable({ rows, filters, footer, state }: { rows: AuditEventRecord[]; filters: ReactNode; footer: ReactNode; state?: ReactNode }) {
  return <DataTable caption="Audit events" columns={columns} rows={rows} rowKey={row => row.id} filters={filters} footer={footer} state={state} minWidth={1000} />;
}
