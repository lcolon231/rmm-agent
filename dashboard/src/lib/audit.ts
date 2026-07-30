// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import {
  AUDIT_PAGE_SIZE,
  type AuditAnchorPublication,
  type AuditAnchorRecord,
  type AuditAnchorVerification,
  type AuditChainVerification,
  type AuditEventRecord,
  type AuditPublicationStatus,
  type AuditQuery,
} from "@/lib/audit-core";
import { nodelinkApiRequest } from "@/lib/nodelink-api";

export type AuditEventPage = {
  items: AuditEventRecord[];
  /** Sequence ceiling this page was taken against; null on an empty chain. */
  before_seq: number | null;
  page: number;
  page_size: number;
  total: number;
};

export type AuditAnchorReceipts = {
  anchor_id: string;
  merkle_root: string;
  publications: AuditAnchorPublication[];
};

export async function getAuditEventTypes(sessionToken: string) {
  const body = await nodelinkApiRequest<{ items: string[] }>("/api/v1/audit/event-types", {
    method: "GET",
    sessionToken,
  });
  return body.items;
}

export async function getAuditEventPage(sessionToken: string, query: AuditQuery) {
  const params = new URLSearchParams({
    page: String(query.page),
    page_size: String(AUDIT_PAGE_SIZE),
  });
  if (query.beforeSeq) params.set("before_seq", String(query.beforeSeq));
  if (query.eventType) params.set("event_type", query.eventType);
  if (query.actor) params.set("actor", query.actor);
  if (query.agentId) params.set("agent_id", query.agentId);
  if (query.organizationId) params.set("organization_id", query.organizationId);
  // The API takes datetimes; a calendar day filter is inclusive of its whole
  // UTC day, so the upper bound is the last instant of the selected date.
  if (query.dateFrom) params.set("date_from", `${query.dateFrom}T00:00:00Z`);
  if (query.dateTo) params.set("date_to", `${query.dateTo}T23:59:59Z`);
  return nodelinkApiRequest<AuditEventPage>(`/api/v1/audit/events?${params}`, {
    method: "GET",
    sessionToken,
  });
}

export async function getAuditEvent(sessionToken: string, eventId: string) {
  return nodelinkApiRequest<AuditEventRecord>(
    `/api/v1/audit/events/${encodeURIComponent(eventId)}`,
    { method: "GET", sessionToken },
  );
}

export async function verifyAuditChain(sessionToken: string) {
  return nodelinkApiRequest<AuditChainVerification>("/api/v1/audit/verify", {
    method: "GET",
    sessionToken,
  });
}

export async function getAuditAnchors(sessionToken: string) {
  return nodelinkApiRequest<AuditAnchorRecord[]>("/api/v1/audit/anchors", {
    method: "GET",
    sessionToken,
  });
}

export async function verifyAuditAnchor(sessionToken: string, anchorId: string) {
  return nodelinkApiRequest<AuditAnchorVerification>(
    `/api/v1/audit/anchors/${encodeURIComponent(anchorId)}/verify`,
    { method: "GET", sessionToken },
  );
}

export async function getAuditAnchorReceipts(sessionToken: string, anchorId: string) {
  return nodelinkApiRequest<AuditAnchorReceipts>(
    `/api/v1/audit/anchors/${encodeURIComponent(anchorId)}/receipt`,
    { method: "GET", sessionToken },
  );
}

export async function getAuditPublicationStatus(sessionToken: string) {
  return nodelinkApiRequest<AuditPublicationStatus>("/api/v1/audit/publication-status", {
    method: "GET",
    sessionToken,
  });
}
