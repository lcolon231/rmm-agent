// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import type {
  InventoryDiffRecord,
  InventoryRecord,
  InventorySectionRecord,
} from "@/lib/inventory-core";
import { nodelinkApiRequest } from "@/lib/nodelink-api";

export type InventoryHistoryPage = {
  agent_id: string;
  section: string;
  items: InventorySectionRecord[];
  page: number;
  page_size: number;
  total: number;
};

export async function getEndpointInventory(sessionToken: string, endpointId: string) {
  return nodelinkApiRequest<InventoryRecord>(
    `/api/v1/endpoints/${encodeURIComponent(endpointId)}/inventory`,
    { method: "GET", sessionToken },
  );
}

export async function getInventoryHistory(
  sessionToken: string,
  endpointId: string,
  section: string,
  page = 1,
) {
  const params = new URLSearchParams({ page: String(page), page_size: "25" });
  return nodelinkApiRequest<InventoryHistoryPage>(
    `/api/v1/endpoints/${encodeURIComponent(endpointId)}/inventory/${encodeURIComponent(section)}/history?${params}`,
    { method: "GET", sessionToken },
  );
}

export async function getInventoryDiff(
  sessionToken: string,
  endpointId: string,
  section: string,
  range?: { from?: string; to?: string },
) {
  const params = new URLSearchParams();
  if (range?.from) params.set("from_snapshot", range.from);
  if (range?.to) params.set("to_snapshot", range.to);
  const query = params.toString();
  return nodelinkApiRequest<InventoryDiffRecord>(
    `/api/v1/endpoints/${encodeURIComponent(endpointId)}/inventory/${encodeURIComponent(section)}/diff${query ? `?${query}` : ""}`,
    { method: "GET", sessionToken },
  );
}
