// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import type { EnrollmentTokenStatus } from "@/lib/enrollment-core";
import { nodelinkApiRequest } from "@/lib/nodelink-api";

export type EnrollmentAgent = {
  id: string;
  site_id: string;
  name: string;
  hostname: string;
  os: string;
  os_version: string;
  agent_version: string;
  architecture: string;
  environment: string | null;
  labels: string[];
  owner_user_id: string | null;
  enrolled_by_token_id: string | null;
  credential_fingerprint: string | null;
  credential_issued_at: string | null;
  credential_expires_at: string | null;
  command_envelope_versions: string[];
  status: "pending" | "online" | "offline";
  trust_state: "active" | "quarantined" | "revoked";
  trust_state_reason: string | null;
  trust_state_changed_at: string | null;
  trust_state_changed_by: string | null;
  last_seen_at: string | null;
  enrolled_at: string;
  revoked_at: string | null;
};

export type EnrollmentTokenMetadata = {
  id: string;
  site_id: string;
  organization_id: string;
  organization_name: string;
  site_name: string;
  masked_token: string;
  name: string;
  description: string | null;
  assigned_user_id: string | null;
  assigned_user_email: string | null;
  environment: string | null;
  hostname_restriction: string | null;
  agent_name_restriction: string | null;
  labels: string[];
  max_uses: number;
  use_count: number;
  expires_at: string | null;
  created_at: string;
  created_by_id: string | null;
  created_by_email: string | null;
  last_used_at: string | null;
  revoked_at: string | null;
  revoked_by_id: string | null;
  revoked_by_email: string | null;
  status: EnrollmentTokenStatus;
  notes: string | null;
};

export type EnrollmentDashboard = {
  total_agents: number;
  active_agents: number;
  offline_agents: number;
  revoked_agents: number;
  active_enrollment_tokens: number;
  expired_tokens: number;
  recently_enrolled_agents: EnrollmentAgent[];
  recent_enrollment_failures: number;
};

export type AuditEvent = {
  id: string;
  seq: number | null;
  ts: string;
  actor: string;
  actor_user_id: string | null;
  action: string;
  agent_id: string | null;
  enrollment_token_id: string | null;
  organization_id: string | null;
  source_ip: string | null;
  detail: Record<string, unknown>;
};

export async function getEnrollmentDashboard(sessionToken: string) {
  return nodelinkApiRequest<EnrollmentDashboard>("/api/v1/enrollment-dashboard", {
    method: "GET",
    sessionToken,
  });
}

export async function getEnrollmentTokens(
  sessionToken: string,
  query: { page?: number; search?: string; status?: EnrollmentTokenStatus } = {},
) {
  const params = new URLSearchParams({ page: String(query.page ?? 1), page_size: "25" });
  if (query.search) params.set("search", query.search);
  if (query.status) params.set("status", query.status);
  return nodelinkApiRequest<{ items: EnrollmentTokenMetadata[]; page: number; page_size: number; total: number }>(
    `/api/v1/enrollment-tokens?${params}`,
    { method: "GET", sessionToken },
  );
}

export async function getEnrollmentAgents(sessionToken: string) {
  return nodelinkApiRequest<EnrollmentAgent[]>("/api/v1/agents", {
    method: "GET",
    sessionToken,
  });
}

export async function getEnrollmentAgent(sessionToken: string, id: string) {
  return nodelinkApiRequest<EnrollmentAgent>(`/api/v1/agents/${encodeURIComponent(id)}`, {
    method: "GET",
    sessionToken,
  });
}

export async function getAuditEvents(
  sessionToken: string,
  query: { agentId?: string; eventType?: string; page?: number } = {},
) {
  const params = new URLSearchParams({ page: String(query.page ?? 1), page_size: "50" });
  if (query.agentId) params.set("agent_id", query.agentId);
  if (query.eventType) params.set("event_type", query.eventType);
  return nodelinkApiRequest<{ items: AuditEvent[]; page: number; page_size: number; total: number }>(
    `/api/v1/audit/events?${params}`,
    { method: "GET", sessionToken },
  );
}
