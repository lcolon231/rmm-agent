// SPDX-License-Identifier: AGPL-3.0-only

import { Filter, KeyRound, Search } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";

import { RevokeAction } from "@/components/enrollment/revoke-action";
import { getDashboardSession } from "@/lib/dashboard-session";
import { canManageEnrollment, formatEnrollmentDateTime, statusLabel, type EnrollmentTokenStatus } from "@/lib/enrollment-core";
import { getEnrollmentTokens } from "@/lib/enrollment";

export default async function EnrollmentTokensPage({ searchParams }: { searchParams: Promise<{ page?: string; search?: string; status?: string }> }) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");
  const query = await searchParams;
  const status = ["active", "used", "expired", "revoked"].includes(query.status ?? "") ? query.status as EnrollmentTokenStatus : undefined;
  const page = /^\d+$/.test(query.page ?? "") ? Math.max(1, Number(query.page)) : 1;
  const search = query.search?.slice(0, 100);
  const data = await getEnrollmentTokens(session.sessionToken, { page, search, status });
  const canManage = canManageEnrollment(session.operator.role);
  return (
    <>
      <header className="enrollment-page-head">
        <div><span>Temporary credentials</span><h1>Enrollment tokens</h1><p>Issue, scope, monitor, and revoke installer credentials. Plaintext is never retrievable.</p></div>
        {canManage ? <Link className="enrollment-primary-link" href="/enrollment/tokens/new"><KeyRound size={17} /> Create token</Link> : null}
      </header>
      <form className="enrollment-filter" method="get">
        <label><Search size={16} /><span className="sr-only">Search tokens</span><input defaultValue={search} name="search" placeholder="Search name or description" /></label>
        <label><Filter size={16} /><span className="sr-only">Filter by status</span><select defaultValue={status ?? ""} name="status"><option value="">All statuses</option><option value="active">Active</option><option value="used">Used</option><option value="expired">Expired</option><option value="revoked">Revoked</option></select></label>
        <button type="submit">Apply</button>
      </form>
      <section className="enrollment-panel">
        <header><div><span>Credential register</span><h2>{data.total} token{data.total === 1 ? "" : "s"}</h2></div><small>Page {data.page}</small></header>
        {data.items.length === 0 ? <div className="enrollment-empty"><KeyRound size={24} /><h3>No matching tokens</h3><p>Create a short-lived token or clear the current filters.</p></div> : (
          <div className="enrollment-table-wrap"><table><thead><tr><th>Token</th><th>Assignment</th><th>Status</th><th>Usage</th><th>Expires</th><th>Created by</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>
            {data.items.map((token) => <tr key={token.id}>
              <td><strong>{token.name}</strong><code>{token.masked_token}</code>{token.labels.length ? <small>{token.labels.join(" · ")}</small> : null}</td>
              <td>{token.organization_name}<small>{token.site_name}{token.environment ? ` · ${token.environment}` : ""}</small></td>
              <td><span className={`enrollment-badge ${token.status}`}>{statusLabel(token.status)}</span></td>
              <td><strong>{token.use_count} / {token.max_uses}</strong><small>{token.last_used_at ? `Last ${formatEnrollmentDateTime(token.last_used_at)}` : "Never used"}</small></td>
              <td>{formatEnrollmentDateTime(token.expires_at, "Legacy / unavailable")}</td>
              <td>{token.created_by_email ?? "Legacy / system"}<small>{formatEnrollmentDateTime(token.created_at, "Legacy / unavailable")}</small></td>
              <td>{canManage && token.status === "active" ? <RevokeAction endpoint={`/api/enrollment-tokens/${token.id}/revoke`} label="Revoke token" subject={token.name} /> : null}</td>
            </tr>)}
          </tbody></table></div>
        )}
        <footer className="enrollment-pagination">
          {page > 1 ? <Link href={`/enrollment/tokens?page=${page - 1}${search ? `&search=${encodeURIComponent(search)}` : ""}${status ? `&status=${status}` : ""}`}>Previous</Link> : <span />}
          {page * data.page_size < data.total ? <Link href={`/enrollment/tokens?page=${page + 1}${search ? `&search=${encodeURIComponent(search)}` : ""}${status ? `&status=${status}` : ""}`}>Next</Link> : null}
        </footer>
      </section>
    </>
  );
}
