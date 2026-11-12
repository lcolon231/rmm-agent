// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Presentation helpers for the Administration screens (Enrollment, Operators,
 * Security keys and MFA, Break-glass). Pure: no fetching, no React.
 */

import type { EnrollmentTokenStatus } from "./enrollment-core.ts";
import type { OperatorRecord, OperatorRole } from "./operator-management-core.ts";

export type AdminTone = "ok" | "warn" | "crit" | "off" | "info";
export type Badge = { tone: AdminTone; label: string };

export type AgentCheckIn = "pending" | "online" | "offline";
export type AgentTrust = "active" | "quarantined" | "revoked";

/** Check-in state only; it says nothing about health or alerts. */
export function agentCheckInBadge(status: AgentCheckIn): Badge {
  if (status === "online") return { tone: "ok", label: "Active" };
  if (status === "offline") return { tone: "off", label: "Offline" };
  return { tone: "info", label: "Waiting" };
}

/** Never defaults to a good state: anything unrecognised reads as needing review. */
export function agentTrustBadge(trust: AgentTrust): Badge & { detail: string } {
  if (trust === "active") return { tone: "ok", label: "Active", detail: "Trusted to receive signed commands." };
  if (trust === "revoked") return { tone: "crit", label: "Revoked", detail: "Its credentials were revoked; it can no longer receive commands." };
  return { tone: "warn", label: "Needs review", detail: "Quarantined: trust must be restored before it is sent commands." };
}

/**
 * Order inside one page: quarantined first, then offline, waiting, active,
 * and revoked agents last because they no longer need anything.
 */
export function agentAttentionRank(agent: { status: AgentCheckIn; trust_state: AgentTrust }): number {
  if (agent.trust_state === "revoked") return 4;
  if (agent.trust_state !== "active") return 0;
  if (agent.status === "offline") return 1;
  if (agent.status === "pending") return 2;
  return 3;
}

export function sortAgentsByAttention<T extends { status: AgentCheckIn; trust_state: AgentTrust }>(agents: readonly T[]): T[] {
  return agents
    .map((agent, index) => ({ agent, index }))
    .sort((a, b) => agentAttentionRank(a.agent) - agentAttentionRank(b.agent) || a.index - b.index)
    .map(({ agent }) => agent);
}

export function countAgents(agents: ReadonlyArray<{ status: AgentCheckIn; trust_state: AgentTrust }>) {
  let online = 0;
  let offline = 0;
  let waiting = 0;
  let revoked = 0;
  for (const agent of agents) {
    if (agent.trust_state === "revoked") {
      revoked += 1;
      continue;
    }
    if (agent.status === "online") online += 1;
    else if (agent.status === "offline") offline += 1;
    else waiting += 1;
  }
  return { online, offline, waiting, revoked };
}

/** "Used" is outside the fixed vocabulary on purpose: no listed word means "all uses consumed". */
export function tokenStatusBadge(status: EnrollmentTokenStatus): Badge {
  if (status === "active") return { tone: "ok", label: "Active" };
  if (status === "revoked") return { tone: "crit", label: "Revoked" };
  if (status === "expired") return { tone: "off", label: "Expired" };
  return { tone: "off", label: "Used" };
}

export type TokensQuery = { page: number; search?: string; status?: EnrollmentTokenStatus };

/** Same parameter names and order as the old Previous/Next links. */
export function tokensHref(query: TokensQuery, patch: Partial<TokensQuery> = {}): string {
  const next = { ...query, ...patch };
  const params = new URLSearchParams();
  if (next.page > 1) params.set("page", String(next.page));
  if (next.search) params.set("search", next.search);
  if (next.status) params.set("status", next.status);
  const qs = params.toString();
  return qs ? `/enrollment/tokens?${qs}` : "/enrollment/tokens";
}

export type OperatorFilter = "all" | OperatorRole | "disabled";

export function filterOperators(operators: readonly OperatorRecord[], filter: OperatorFilter, search: string): OperatorRecord[] {
  const term = search.trim().toLowerCase();
  return operators.filter((operator) => {
    if (term && !operator.email.toLowerCase().includes(term)) return false;
    if (filter === "all") return true;
    if (filter === "disabled") return operator.disabled;
    return operator.role === filter;
  });
}

export function operatorCounts(operators: readonly OperatorRecord[]) {
  return {
    total: operators.length,
    disabled: operators.filter((operator) => operator.disabled).length,
    admins: operators.filter((operator) => operator.role === "admin" && !operator.disabled).length,
    technicians: operators.filter((operator) => operator.role === "operator").length,
    readonly: operators.filter((operator) => operator.role === "readonly").length,
    scripts: operators.filter((operator) => operator.script_execution_scope !== null).length,
  };
}

/** Reasons the API accepts for revocations: 3 to 500 characters after trimming. */
export function reasonProblem(reason: string): string | null {
  const length = reason.trim().length;
  if (length < 3) return "Enter a reason of at least three characters.";
  if (length > 500) return "Keep the reason to 500 characters or fewer.";
  return null;
}
