// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { ChevronLeft, ChevronRight, KeyRound } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";

import { ModalLayerProvider, useLayeredDrawer } from "@/components/admin/admin-ui";
import { Mono } from "@/components/admin/card";
import { cx, focusRing } from "@/components/ui/cx";
import { DataTable, PrimaryCell, TableFooter, type Column } from "@/components/ui/data-table";
import { DefinitionList, Drawer } from "@/components/ui/drawer";
import { FilterBar, FilterChip } from "@/components/ui/filter-bar";
import { EmptyState } from "@/components/ui/states";
import { StatusBadge } from "@/components/ui/status-badge";
import { tokenStatusBadge, tokensHref, type TokensQuery } from "@/lib/admin-screens-core";
import type { EnrollmentTokenMetadata } from "@/lib/enrollment";
import { formatEnrollmentDateTime, type EnrollmentTokenStatus } from "@/lib/enrollment-core";

import { RevokeAction } from "./revoke-action";

const CHIPS: Array<{ label: string; status: EnrollmentTokenStatus | undefined }> = [
  { label: "All", status: undefined },
  { label: "Active", status: "active" },
  { label: "Used", status: "used" },
  { label: "Expired", status: "expired" },
  { label: "Revoked", status: "revoked" },
];

function SearchForm({ query }: { query: TokensQuery }) {
  // Plain GET form: works before hydration and keeps the status filter.
  return (
    <form role="search" action="/enrollment/tokens" method="get" className="w-full max-w-[320px] min-w-[200px] flex-1">
      {query.status ? <input type="hidden" name="status" value={query.status} /> : null}
      <input
        type="search"
        name="search"
        maxLength={100}
        defaultValue={query.search ?? ""}
        aria-label="Search tokens by name or description"
        placeholder="Search name or description"
        className={cx("h-10 w-full rounded-lg border border-(--line-strong) bg-(--paper) px-3 text-sm text-(--ink)", focusRing)}
      />
    </form>
  );
}

function Pagination({ query, total, pageSize }: { query: TokensQuery; total: number; pageSize: number }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const iconLink = cx("flex size-9 items-center justify-center rounded-lg border border-(--line-strong) bg-(--paper) text-(--slate) hover:bg-(--primary-tint)", focusRing);
  const disabled = "flex size-9 items-center justify-center rounded-lg border border-(--line) bg-(--fog) text-(--muted)";
  return (
    <>
      {query.page > 1 ? (
        <Link href={tokensHref(query, { page: query.page - 1 })} aria-label="Previous page" className={iconLink}>
          <ChevronLeft size={16} aria-hidden="true" />
        </Link>
      ) : (
        <span aria-hidden="true" className={disabled}>
          <ChevronLeft size={16} />
        </span>
      )}
      <span className="px-2">
        Page {Math.min(query.page, pages)} of {pages}
      </span>
      {query.page * pageSize < total ? (
        <Link href={tokensHref(query, { page: query.page + 1 })} aria-label="Next page" className={iconLink}>
          <ChevronRight size={16} aria-hidden="true" />
        </Link>
      ) : (
        <span aria-hidden="true" className={disabled}>
          <ChevronRight size={16} />
        </span>
      )}
    </>
  );
}

function TokenDrawer({
  token,
  canManage,
  onClose,
  onRevoked,
}: {
  token: EnrollmentTokenMetadata;
  canManage: boolean;
  onClose: () => void;
  onRevoked: () => void;
}) {
  const badge = tokenStatusBadge(token.status);
  return (
    <Drawer
      open
      onClose={onClose}
      context={`${token.organization_name} · ${token.site_name}`}
      title={token.name}
      sub={<Mono>{token.masked_token}</Mono>}
      footer={
        canManage && token.status === "active" ? (
          <RevokeAction endpoint={`/api/enrollment-tokens/${token.id}/revoke`} kind="token" label="Revoke token" subject={token.name} onRevoked={onRevoked} />
        ) : undefined
      }
      record={`Created ${formatEnrollmentDateTime(token.created_at, "at an unrecorded time")} by ${token.created_by_email ?? "an unrecorded operator"}${
        token.revoked_at ? ` · revoked ${formatEnrollmentDateTime(token.revoked_at)} by ${token.revoked_by_email ?? "an unrecorded operator"}` : ""
      }`}
    >
      <div>
        <StatusBadge tone={badge.tone}>{badge.label}</StatusBadge>
      </div>
      {token.description ? <p className="m-0">{token.description}</p> : null}
      <DefinitionList
        items={[
          { term: "Uses", value: `${token.use_count} of ${token.max_uses}` },
          { term: "Last used", value: token.last_used_at ? formatEnrollmentDateTime(token.last_used_at) : "Never used" },
          { term: "Expires", value: formatEnrollmentDateTime(token.expires_at, "Not recorded") },
          { term: "Environment", value: token.environment ?? "Any" },
          { term: "Hostname must be", value: token.hostname_restriction ? <Mono>{token.hostname_restriction}</Mono> : "Any" },
          { term: "Agent name must be", value: token.agent_name_restriction ? <Mono>{token.agent_name_restriction}</Mono> : "Any" },
          { term: "Assigned to", value: token.assigned_user_email ?? token.assigned_user_id ?? "Nobody" },
          { term: "Labels", value: token.labels.length ? token.labels.join(", ") : "None" },
        ]}
      />
      <p className="m-0 text-xs text-(--muted)">The token itself was shown once when it was created and cannot be shown again.</p>
    </Drawer>
  );
}

export function EnrollmentTokensView({
  tokens,
  total,
  pageSize,
  query,
  canManage,
}: {
  tokens: EnrollmentTokenMetadata[];
  total: number;
  pageSize: number;
  query: TokensQuery;
  canManage: boolean;
}) {
  const router = useRouter();
  const drawer = useLayeredDrawer<EnrollmentTokenMetadata>();
  const filtered = Boolean(query.status || query.search);

  const columns: Column<EnrollmentTokenMetadata>[] = [
    {
      key: "token",
      header: "Token",
      cell: (token) => <PrimaryCell title={token.name} sub={<Mono>{token.masked_token}</Mono>} />,
    },
    {
      key: "state",
      header: "State",
      cell: (token) => {
        const badge = tokenStatusBadge(token.status);
        return <StatusBadge tone={badge.tone}>{badge.label}</StatusBadge>;
      },
    },
    { key: "site", header: "Site", cell: (token) => <PrimaryCell title={token.site_name} sub={token.organization_name} /> },
    {
      key: "uses",
      header: "Uses",
      cell: (token) => <PrimaryCell title={`${token.use_count} of ${token.max_uses}`} sub={token.last_used_at ? `Last ${formatEnrollmentDateTime(token.last_used_at)}` : "Never used"} />,
    },
    { key: "created", header: "Created by", cell: (token) => <PrimaryCell title={token.created_by_email ?? "Not recorded"} sub={formatEnrollmentDateTime(token.created_at, "Not recorded")} /> },
    { key: "expires", header: "Expires", cell: (token) => formatEnrollmentDateTime(token.expires_at, "Not recorded") },
  ];

  return (
    <ModalLayerProvider onChange={drawer.setLayerOpen}>
      <DataTable
        caption="Enrollment tokens"
        columns={columns}
        rows={tokens}
        rowKey={(token) => token.id}
        rowLabel={(token) => `Preview ${token.name}`}
        onRowSelect={drawer.open}
        minWidth={1000}
        state={
          tokens.length === 0 ? (
            filtered ? (
              <EmptyState title="No tokens match" body="Try a different name, or clear the filters." actionLabel="Clear filters" onAction={() => router.push(tokensHref({ page: 1 }))} />
            ) : (
              <EmptyState icon={KeyRound} title="No enrollment tokens yet" body="Create a short-lived token, or download an installer that carries its own." />
            )
          ) : undefined
        }
        filters={
          <FilterBar>
            <SearchForm query={query} />
            <div role="group" aria-label="Filter by state" className="flex flex-wrap gap-2">
              {CHIPS.map((chip) => (
                <FilterChip key={chip.label} href={tokensHref(query, { status: chip.status, page: 1 })} selected={query.status === chip.status}>
                  {chip.label}
                </FilterChip>
              ))}
            </div>
          </FilterBar>
        }
        footer={tokens.length > 0 ? <TableFooter shown={tokens.length} total={total} sortNote="newest first" pagination={<Pagination query={query} total={total} pageSize={pageSize} />} /> : null}
      />
      {drawer.selected ? <TokenDrawer token={drawer.selected} canManage={canManage} onClose={drawer.close} onRevoked={drawer.forceClose} /> : null}
    </ModalLayerProvider>
  );
}
