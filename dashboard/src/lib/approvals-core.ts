// SPDX-License-Identifier: AGPL-3.0-only

/** Approval workflow presentation and validation (issue #64).
 *
 * The management service is the sole authority on every decision here: it
 * refuses self-approval, counts distinct identities, re-checks each approver's
 * authority at dispatch, and binds the approval to the reviewed payload. This
 * module exists so a reviewer can see the same answer *before* they click, and
 * so a malformed or secret-adjacent field can never reach the UI — every parser
 * fails closed (returns null) on an unexpected shape.
 *
 * `canDecide` in particular is a hint, never a gate. It hides a button the
 * server would refuse anyway; the server refusing it is what makes the control
 * real.
 */

export type ApprovalStatus =
  | "pending"
  | "approved"
  | "rejected"
  | "cancelled"
  | "expired"
  | "consumed";

export type ApprovalScope = "global" | "client" | "site" | "agent";

export type ApprovalPolicy = {
  id: string;
  name: string;
  scope: ApprovalScope;
  scope_id: string | null;
  command_kinds: string[];
  required_approvals: number;
  request_ttl_seconds: number;
  enabled: boolean;
  created_at: string;
  created_by: string | null;
};

export type ApprovalDecision = {
  id: string;
  operator_id: string;
  operator_email: string;
  decision: "approve" | "reject";
  reason: string | null;
  created_at: string;
};

export type ApprovalRequest = {
  id: string;
  agent_id: string;
  client_id: string | null;
  site_id: string | null;
  kind: string;
  status: ApprovalStatus;
  payload_sha256: string;
  policy_id: string | null;
  required_approvals: number;
  approvals_recorded: number;
  requested_by_email: string;
  requested_by_operator_id: string | null;
  reason: string;
  created_at: string;
  expires_at: string;
  decided_at: string | null;
  consumed_at: string | null;
};

export type ApprovalRequestDetail = ApprovalRequest & {
  payload_keys: string[];
  decisions: ApprovalDecision[];
  closed_at: string | null;
  closed_by_email: string | null;
  consumed_command_id: string | null;
};

export const MIN_DECISION_REASON_LENGTH = 10;
export const MAX_DECISION_REASON_LENGTH = 512;

const STATUSES: ApprovalStatus[] = [
  "pending",
  "approved",
  "rejected",
  "cancelled",
  "expired",
  "consumed",
];
const SCOPES: ApprovalScope[] = ["global", "client", "site", "agent"];

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function stringOrNull(value: unknown): string | null | undefined {
  if (value === null || value === undefined) return null;
  return typeof value === "string" ? value : undefined;
}

function stringList(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  return value.every((entry) => typeof entry === "string") ? (value as string[]) : null;
}

export function approvalPolicyFromUnknown(value: unknown): ApprovalPolicy | null {
  if (!isRecord(value)) return null;
  const { id, name, scope, required_approvals: required } = value;
  if (typeof id !== "string" || !id) return null;
  if (typeof name !== "string" || !name) return null;
  if (typeof scope !== "string" || !SCOPES.includes(scope as ApprovalScope)) return null;
  const kinds = stringList(value.command_kinds);
  if (!kinds) return null;
  if (typeof required !== "number" || !Number.isInteger(required)) return null;
  const ttl = value.request_ttl_seconds;
  if (typeof ttl !== "number" || !Number.isInteger(ttl)) return null;
  if (typeof value.enabled !== "boolean") return null;
  if (typeof value.created_at !== "string") return null;
  const scopeId = stringOrNull(value.scope_id);
  const createdBy = stringOrNull(value.created_by);
  if (scopeId === undefined || createdBy === undefined) return null;
  return {
    id,
    name,
    scope: scope as ApprovalScope,
    scope_id: scopeId,
    command_kinds: kinds,
    required_approvals: required,
    request_ttl_seconds: ttl,
    enabled: value.enabled,
    created_at: value.created_at,
    created_by: createdBy,
  };
}

export function approvalRequestFromUnknown(value: unknown): ApprovalRequest | null {
  if (!isRecord(value)) return null;
  const { id, agent_id: agentId, kind, status } = value;
  if (typeof id !== "string" || !id) return null;
  if (typeof agentId !== "string" || !agentId) return null;
  if (typeof kind !== "string" || !kind) return null;
  if (typeof status !== "string" || !STATUSES.includes(status as ApprovalStatus)) return null;
  const required = value.required_approvals;
  const recorded = value.approvals_recorded;
  if (typeof required !== "number" || !Number.isInteger(required)) return null;
  if (typeof recorded !== "number" || !Number.isInteger(recorded)) return null;
  if (typeof value.payload_sha256 !== "string") return null;
  if (typeof value.requested_by_email !== "string") return null;
  if (typeof value.reason !== "string") return null;
  if (typeof value.created_at !== "string") return null;
  if (typeof value.expires_at !== "string") return null;
  const clientId = stringOrNull(value.client_id);
  const siteId = stringOrNull(value.site_id);
  const policyId = stringOrNull(value.policy_id);
  const requesterId = stringOrNull(value.requested_by_operator_id);
  const decidedAt = stringOrNull(value.decided_at);
  const consumedAt = stringOrNull(value.consumed_at);
  if (
    clientId === undefined ||
    siteId === undefined ||
    policyId === undefined ||
    requesterId === undefined ||
    decidedAt === undefined ||
    consumedAt === undefined
  ) {
    return null;
  }
  return {
    id,
    agent_id: agentId,
    client_id: clientId,
    site_id: siteId,
    kind,
    status: status as ApprovalStatus,
    payload_sha256: value.payload_sha256,
    policy_id: policyId,
    required_approvals: required,
    approvals_recorded: recorded,
    requested_by_email: value.requested_by_email,
    requested_by_operator_id: requesterId,
    reason: value.reason,
    created_at: value.created_at,
    expires_at: value.expires_at,
    decided_at: decidedAt,
    consumed_at: consumedAt,
  };
}

export function approvalRequestListFromUnknown(value: unknown): ApprovalRequest[] | null {
  if (!Array.isArray(value)) return null;
  const parsed = value.map(approvalRequestFromUnknown);
  return parsed.every((entry): entry is ApprovalRequest => entry !== null) ? parsed : null;
}

export function approvalPolicyListFromUnknown(value: unknown): ApprovalPolicy[] | null {
  if (!Array.isArray(value)) return null;
  const parsed = value.map(approvalPolicyFromUnknown);
  return parsed.every((entry): entry is ApprovalPolicy => entry !== null) ? parsed : null;
}

function decisionFromUnknown(value: unknown): ApprovalDecision | null {
  if (!isRecord(value)) return null;
  const { id, operator_id: operatorId, operator_email: email, decision } = value;
  if (typeof id !== "string" || !id) return null;
  if (typeof operatorId !== "string" || !operatorId) return null;
  if (typeof email !== "string" || !email) return null;
  if (decision !== "approve" && decision !== "reject") return null;
  if (typeof value.created_at !== "string") return null;
  const reason = stringOrNull(value.reason);
  if (reason === undefined) return null;
  return {
    id,
    operator_id: operatorId,
    operator_email: email,
    decision,
    reason,
    created_at: value.created_at,
  };
}

export function approvalRequestDetailFromUnknown(
  value: unknown,
): ApprovalRequestDetail | null {
  const summary = approvalRequestFromUnknown(value);
  if (!summary || !isRecord(value)) return null;
  const keys = stringList(value.payload_keys);
  if (!keys) return null;
  if (!Array.isArray(value.decisions)) return null;
  const decisions = value.decisions.map(decisionFromUnknown);
  if (!decisions.every((entry): entry is ApprovalDecision => entry !== null)) return null;
  const closedAt = stringOrNull(value.closed_at);
  const closedBy = stringOrNull(value.closed_by_email);
  const commandId = stringOrNull(value.consumed_command_id);
  if (closedAt === undefined || closedBy === undefined || commandId === undefined) {
    return null;
  }
  return {
    ...summary,
    payload_keys: keys,
    decisions,
    closed_at: closedAt,
    closed_by_email: closedBy,
    consumed_command_id: commandId,
  };
}

/** Whether this viewer could plausibly decide this request.
 *
 * A UI hint only. It mirrors the two rules a reviewer can check from the data
 * they already have — the request is still open, and they are neither the
 * requester nor an identity that has already voted. Tenant role, script
 * permission, and approver eligibility are re-evaluated server side and are
 * deliberately not duplicated here, because a stale local copy of an
 * authorization rule is worse than no copy.
 */
export function canDecide(
  request: ApprovalRequestDetail,
  viewerOperatorId: string | null,
): boolean {
  if (request.status !== "pending") return false;
  if (!viewerOperatorId) return false;
  if (request.requested_by_operator_id === viewerOperatorId) return false;
  return !request.decisions.some((entry) => entry.operator_id === viewerOperatorId);
}

/** Why the decide controls are hidden, phrased for the person looking at them. */
export function decideBlockedReason(
  request: ApprovalRequestDetail,
  viewerOperatorId: string | null,
): string | null {
  if (canDecide(request, viewerOperatorId)) return null;
  if (request.status !== "pending") return `This request is ${statusLabel(request.status).toLowerCase()}.`;
  if (!viewerOperatorId) return "Your identity could not be resolved.";
  if (request.requested_by_operator_id === viewerOperatorId) {
    return "You raised this request, so you cannot approve it.";
  }
  return "You have already recorded a decision on this request.";
}

export function statusLabel(status: ApprovalStatus): string {
  switch (status) {
    case "pending":
      return "Awaiting approval";
    case "approved":
      return "Approved";
    case "rejected":
      return "Rejected";
    case "cancelled":
      return "Cancelled";
    case "expired":
      return "Expired";
    case "consumed":
      return "Executed";
  }
}

/** The queue ordering a reviewer wants: actionable first, then most urgent. */
export function sortForReview<T extends ApprovalRequest>(requests: T[]): T[] {
  const rank: Record<ApprovalStatus, number> = {
    pending: 0,
    approved: 1,
    expired: 2,
    rejected: 3,
    cancelled: 3,
    consumed: 4,
  };
  return [...requests].sort((left, right) => {
    if (rank[left.status] !== rank[right.status]) return rank[left.status] - rank[right.status];
    return Date.parse(left.expires_at) - Date.parse(right.expires_at);
  });
}

export function isValidDecisionReason(reason: string): boolean {
  const trimmed = reason.trim();
  const size = new TextEncoder().encode(trimmed).length;
  if (size < MIN_DECISION_REASON_LENGTH || size > MAX_DECISION_REASON_LENGTH) return false;
  // Mirrors the server's printable-only rule so the reviewer sees the problem
  // before the request round-trips.
  return ![...trimmed].some((char) => {
    const code = char.codePointAt(0) ?? 0;
    return code < 32 || code === 127;
  });
}

/** Remaining lifetime, rendered for a reviewer deciding whether to act now. */
export function formatTimeRemaining(expiresAt: string, now: Date): string {
  const remaining = Date.parse(expiresAt) - now.getTime();
  if (Number.isNaN(remaining)) return "unknown";
  if (remaining <= 0) return "expired";
  const minutes = Math.floor(remaining / 60_000);
  if (minutes < 60) return `${minutes} min left`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours} h left`;
  return `${Math.floor(hours / 24)} d left`;
}

export function formatApprovalScope(scope: ApprovalScope, scopeId: string | null): string {
  if (scope === "global") return "All tenants";
  const label = scope === "client" ? "Client" : scope === "site" ? "Site" : "Endpoint";
  return scopeId ? `${label} ${scopeId.slice(0, 8)}` : label;
}
