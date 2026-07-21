// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import { nodelinkApiRequest } from "@/lib/nodelink-api";

export type EndpointListItem = {
  id: string;
  hostname: string;
  os: string;
  os_version: string;
  agent_version: string;
  status: "pending" | "online" | "offline";
  last_seen_at: string | null;
  client_id: string;
  client_name: string;
  site_id: string;
  site_name: string;
  cpu_percent: number | null;
  mem_percent: number | null;
  disk_percent: number | null;
  logged_in_user: string | null;
};

export type EndpointListData = {
  items: EndpointListItem[];
  page: number;
  page_size: number;
  total: number;
};

export type EndpointQuery = {
  clientId?: string;
  direction?: "asc" | "desc";
  page?: number;
  search?: string;
  siteId?: string;
  sort?: "last_seen" | "hostname" | "status";
  status?: "online" | "offline" | "pending";
};

export async function getEndpointList(sessionToken: string, options: EndpointQuery = {}): Promise<EndpointListData> {
  const query = new URLSearchParams({ page: String(options.page ?? 1), page_size: "25", sort: options.sort ?? "last_seen", direction: options.direction ?? "desc" });
  if (options.clientId) query.set("client_id", options.clientId);
  if (options.siteId) query.set("site_id", options.siteId);
  if (options.status) query.set("status", options.status);
  if (options.search) query.set("search", options.search);
  return nodelinkApiRequest<EndpointListData>(`/api/v1/endpoints?${query}`, { method: "GET", sessionToken });
}
