// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import {
  listFromUnknown,
  summaryFromUnknown,
  type ComplianceListData,
  type ComplianceState,
  type ComplianceSummary,
} from "@/lib/patch-compliance-core";
import { nodelinkApiRequest } from "@/lib/nodelink-api";

type ComplianceScope = {
  clientId?: string;
  siteId?: string;
};

type ComplianceListOptions = ComplianceScope & {
  state?: ComplianceState;
  search?: string;
  sort?: "hostname" | "state" | "approved_missing" | "scanned_at";
  direction?: "asc" | "desc";
  page?: number;
  pageSize?: number;
};

function appendScope(query: URLSearchParams, options: ComplianceScope): void {
  if (options.clientId) query.set("client_id", options.clientId);
  if (options.siteId) query.set("site_id", options.siteId);
}

export async function getComplianceSummary(
  sessionToken: string,
  options: ComplianceScope = {},
): Promise<ComplianceSummary> {
  const query = new URLSearchParams();
  appendScope(query, options);
  const suffix = query.size > 0 ? `?${query}` : "";
  const value = await nodelinkApiRequest<unknown>(`/api/v1/patch-compliance/summary${suffix}`, {
    method: "GET",
    sessionToken,
  });
  const summary = summaryFromUnknown(value);
  if (!summary) throw new Error("The management service returned an invalid compliance summary.");
  return summary;
}

export async function getComplianceList(
  sessionToken: string,
  options: ComplianceListOptions = {},
): Promise<ComplianceListData> {
  const query = new URLSearchParams();
  appendScope(query, options);
  if (options.state) query.set("state", options.state);
  if (options.search) query.set("search", options.search);
  if (options.sort) query.set("sort", options.sort);
  if (options.direction) query.set("direction", options.direction);
  if (options.page) query.set("page", String(options.page));
  if (options.pageSize) query.set("page_size", String(options.pageSize));
  const suffix = query.size > 0 ? `?${query}` : "";
  const value = await nodelinkApiRequest<unknown>(`/api/v1/patch-compliance${suffix}`, {
    method: "GET",
    sessionToken,
  });
  const report = listFromUnknown(value);
  if (!report) throw new Error("The management service returned an invalid compliance report.");
  return report;
}
