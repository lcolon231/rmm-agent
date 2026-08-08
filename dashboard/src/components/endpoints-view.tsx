// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import {
  AlertTriangle,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  CircleAlert,
  Download,
  Laptop,
  Monitor,
  RefreshCw,
  Search,
} from "lucide-react";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useMemo, useState } from "react";

import type { EndpointListData } from "@/lib/endpoint-list";

function Meter({ value }: { value: number | null }) {
  if (value === null) return <span className="empty-value">—</span>;
  const tone = value >= 90 ? "critical" : value >= 68 ? "warning" : "healthy";
  return (
    <div className="meter" aria-label={`${value}%`}>
      <span>{value}%</span>
      <i>
        <b className={tone} style={{ width: `${value}%` }} />
      </i>
    </div>
  );
}

export function EndpointsView({
  endpointError,
  endpointList,
  endpointSearch,
  endpointSort,
  endpointStatus,
}: {
  endpointError: boolean;
  endpointList: EndpointListData | null;
  endpointSearch: string;
  endpointSort: "last_seen" | "hostname" | "status";
  endpointStatus?: "online" | "offline" | "pending";
}) {
  const router = useRouter();
  const [query, setQuery] = useState(endpointSearch);

  const updateQuery = (changes: Record<string, string | undefined>) => {
    const params = new URLSearchParams(window.location.search);
    for (const [key, value] of Object.entries(changes)) {
      if (value) params.set(key, value);
      else params.delete(key);
    }
    if (!("page" in changes)) params.delete("page");
    const nextQuery = params.toString();
    router.push(nextQuery ? `/endpoints?${nextQuery}` : "/endpoints");
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    updateQuery({ search: query || undefined });
  };

  const items = useMemo(
    () =>
      endpointList?.items.map((endpoint) => ({
        id: endpoint.id,
        name: endpoint.hostname,
        os: [endpoint.os, endpoint.os_version].filter(Boolean).join(" "),
        client: endpoint.client_name,
        site: endpoint.site_name,
        status: endpoint.status === "online" ? "online" : endpoint.status === "offline" ? "offline" : "warning",
        lastSeen: endpoint.last_seen_at
          ? new Intl.DateTimeFormat("en-US", { dateStyle: "medium", timeStyle: "short" }).format(
              new Date(endpoint.last_seen_at),
            )
          : "Never",
        user: endpoint.logged_in_user ?? "—",
        cpu: endpoint.cpu_percent,
        memory: endpoint.mem_percent,
        disk: endpoint.disk_percent,
      })) ?? [],
    [endpointList],
  );

  const exportCsv = () => {
    const rows = [
      ["Endpoint", "Client", "Site", "Status", "Last seen", "User", "CPU", "Memory", "Disk"],
      ...items.map((item) => [
        item.name,
        item.client,
        item.site,
        item.status,
        item.lastSeen,
        item.user,
        item.cpu ?? "",
        item.memory ?? "",
        item.disk ?? "",
      ]),
    ];
    const csv = rows.map((row) => row.map((cell) => `"${String(cell).replaceAll('"', '""')}"`).join(",")).join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "nodelink-endpoints.csv";
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const total = endpointList?.total ?? 0;
  const page = endpointList?.page ?? 1;
  const pageSize = endpointList?.page_size ?? 25;
  const totalPages = Math.ceil(total / pageSize) || 1;

  return (
    <>
      <header className="enrollment-page-head">
        <div>
          <span>Managed Infrastructure</span>
          <h1>Endpoints Inventory</h1>
          <p>
            Complete directory of enrolled Windows agents, live telemetry metrics, identity scope, and diagnostic controls.
          </p>
        </div>
      </header>

      <section className="agent-identity-grid">
        <article>
          <Monitor size={20} />
          <span>Total endpoints</span>
          <strong>{total}</strong>
          <small>Registered agents</small>
        </article>
        <article>
          <CheckCircle2 size={20} />
          <span>Online status</span>
          <strong>{items.filter((i) => i.status === "online").length}</strong>
          <small>Active telemetry</small>
        </article>
        <article>
          <AlertTriangle size={20} />
          <span>Warnings / Offline</span>
          <strong>{items.filter((i) => i.status !== "online").length}</strong>
          <small>Needs inspection</small>
        </article>
      </section>

      <section className="enrollment-panel">
        <header className="fleet-header">
          <div>
            <span>Endpoint controls</span>
            <h2>{total} Endpoint{total === 1 ? "" : "s"}</h2>
          </div>
          <form className="global-search" onSubmit={handleSearchSubmit} style={{ maxWidth: 300 }}>
            <Search size={16} />
            <input
              type="search"
              placeholder="Search hostname, user..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </form>
          <select
            aria-label="Endpoint status"
            value={endpointStatus ?? ""}
            onChange={(e) => updateQuery({ status: e.target.value || undefined })}
          >
            <option value="">All statuses</option>
            <option value="online">Online</option>
            <option value="offline">Offline</option>
            <option value="pending">Pending</option>
          </select>
          <select
            aria-label="Endpoint sort order"
            value={endpointSort}
            onChange={(e) => updateQuery({ sort: e.target.value })}
          >
            <option value="last_seen">Last seen</option>
            <option value="hostname">Hostname</option>
            <option value="status">Status</option>
          </select>
          <button type="button" className="export-button" onClick={exportCsv}>
            <Download size={16} />
            <span>Export CSV</span>
          </button>
        </header>

        {endpointError ? (
          <div className="enrollment-empty">
            <CircleAlert size={24} />
            <p>Endpoint inventory is unavailable. Try refreshing the page.</p>
            <button type="button" className="enrollment-btn-primary" onClick={() => router.refresh()}>
              <RefreshCw size={14} /> Refresh
            </button>
          </div>
        ) : items.length === 0 ? (
          <div className="enrollment-empty">
            <p>No endpoints found matching your criteria.</p>
          </div>
        ) : (
          <div className="enrollment-table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Device / Hostname</th>
                  <th>Client & Site</th>
                  <th>Status</th>
                  <th>Last seen</th>
                  <th>User</th>
                  <th>CPU</th>
                  <th>Memory</th>
                  <th>Disk</th>
                  <th className="text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr key={item.id}>
                    <td>
                      <span className="device-cell">
                        <Laptop size={18} />
                        <span>
                          <strong>{item.name}</strong>
                          <small>{item.os}</small>
                        </span>
                      </span>
                    </td>
                    <td>
                      <span className="stacked-cell">
                        <strong>{item.client}</strong>
                        <small>{item.site}</small>
                      </span>
                    </td>
                    <td>
                      <span className={`status-tag ${item.status}`}>
                        {item.status === "online" ? "Online" : item.status === "offline" ? "Offline" : "Warning"}
                      </span>
                    </td>
                    <td>
                      <small>{item.lastSeen}</small>
                    </td>
                    <td>
                      <code>{item.user}</code>
                    </td>
                    <td>
                      <Meter value={item.cpu} />
                    </td>
                    <td>
                      <Meter value={item.memory} />
                    </td>
                    <td>
                      <Meter value={item.disk} />
                    </td>
                    <td className="text-right">
                      <Link className="schedule-btn run-now" href={`/endpoints/${encodeURIComponent(item.id)}`}>
                        Open endpoint
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <footer className="fleet-footer" style={{ padding: "12px 20px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <small>Showing {items.length} of {total} endpoints</small>
          <div className="pagination" style={{ display: "flex", gap: "6px", alignItems: "center" }}>
            <button
              type="button"
              className="schedule-btn"
              disabled={page <= 1}
              onClick={() => updateQuery({ page: String(page - 1) })}
            >
              <ChevronLeft size={14} />
            </button>
            <span style={{ fontSize: "13px", fontWeight: 500 }}>Page {page} of {totalPages}</span>
            <button
              type="button"
              className="schedule-btn"
              disabled={page >= totalPages}
              onClick={() => updateQuery({ page: String(page + 1) })}
            >
              <ChevronRight size={14} />
            </button>
          </div>
        </footer>
      </section>
    </>
  );
}
