// SPDX-License-Identifier: AGPL-3.0-only
//
// Pure, allowlisting parsers and formatters for patch approval policies (#52).
// Every parser fails closed (returns null) on an unexpected shape so a malformed
// or secret-adjacent field can never reach the UI.

export type PatchScope = "global" | "client" | "site" | "agent";
export type PatchAction = "approve" | "deny" | "defer";
export type PatchDefaultAction = "approve" | "deny";

export type PatchMatch = {
  classifications: string[] | null;
  severities: string[] | null;
  kb_ids: string[] | null;
};

export type PatchRule = {
  key: string;
  action: PatchAction;
  match: PatchMatch;
  defer_days: number | null;
};

export type RebootPolicy = "never" | "if_required" | "forced";

export type PatchApprovalPolicy = {
  id: string;
  name: string;
  scope: PatchScope;
  scope_id: string | null;
  enabled: boolean;
  created_at: string;
  current_version: number;
  rule_count: number;
  default_action: PatchDefaultAction;
  require_maintenance_window: boolean;
  reboot_policy: RebootPolicy;
  max_install_attempts: number;
};

export type PatchApprovalPolicyRevision = {
  id: string;
  version: number;
  default_action: PatchDefaultAction;
  require_maintenance_window: boolean;
  change_note: string | null;
  created_by: string | null;
  created_at: string;
  rules: PatchRule[];
};

export type PatchApprovalPolicyDetail = PatchApprovalPolicy & {
  rules: PatchRule[];
  revisions: PatchApprovalPolicyRevision[];
};

export type PatchUpdateDecision = {
  kb_id: string | null;
  update_id: string | null;
  title: string;
  classification: string | null;
  severity: string | null;
  decision: PatchAction;
  reason: string;
  matched_rule_key: string | null;
};

export type EffectivePatchPolicy = {
  policy_id: string | null;
  policy_name: string | null;
  scope: PatchScope | null;
  default_action: PatchDefaultAction | null;
  require_maintenance_window: boolean;
  decisions: PatchUpdateDecision[];
};

const scopes = new Set<PatchScope>(["global", "client", "site", "agent"]);
const actions = new Set<PatchAction>(["approve", "deny", "defer"]);
const defaults = new Set<PatchDefaultAction>(["approve", "deny"]);
const rebootPolicies = new Set<RebootPolicy>(["never", "if_required", "forced"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isTimestamp(value: unknown): value is string {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

function stringListOrNull(value: unknown): string[] | null | undefined {
  if (value === null || value === undefined) return null;
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) return undefined;
  return value as string[];
}

function matchFromUnknown(value: unknown): PatchMatch | null {
  if (!isRecord(value)) return null;
  const classifications = stringListOrNull(value.classifications);
  const severities = stringListOrNull(value.severities);
  const kb_ids = stringListOrNull(value.kb_ids);
  if (classifications === undefined || severities === undefined || kb_ids === undefined) return null;
  return { classifications, severities, kb_ids };
}

function ruleFromUnknown(value: unknown): PatchRule | null {
  if (!isRecord(value)) return null;
  if (typeof value.key !== "string" || !actions.has(value.action as PatchAction)) return null;
  const match = matchFromUnknown(value.match);
  if (match === null) return null;
  const deferDays = value.defer_days;
  if (deferDays !== null && deferDays !== undefined && !Number.isInteger(deferDays)) return null;
  return {
    key: value.key,
    action: value.action as PatchAction,
    match,
    defer_days: typeof deferDays === "number" ? deferDays : null,
  };
}

function rulesFromUnknown(value: unknown): PatchRule[] | null {
  if (!Array.isArray(value)) return null;
  const rules = value.map(ruleFromUnknown);
  return rules.every((rule): rule is PatchRule => rule !== null) ? rules : null;
}

export function patchPolicyFromUnknown(value: unknown): PatchApprovalPolicy | null {
  if (!isRecord(value)) return null;
  if (
    typeof value.id !== "string"
    || typeof value.name !== "string"
    || !scopes.has(value.scope as PatchScope)
    || (value.scope_id !== null && typeof value.scope_id !== "string")
    || typeof value.enabled !== "boolean"
    || !isTimestamp(value.created_at)
    || !Number.isInteger(value.current_version)
    || !Number.isInteger(value.rule_count)
    || (value.current_version as number) < 0
    || (value.rule_count as number) < 0
    || !defaults.has(value.default_action as PatchDefaultAction)
    || typeof value.require_maintenance_window !== "boolean"
    || !rebootPolicies.has(value.reboot_policy as RebootPolicy)
    || !Number.isInteger(value.max_install_attempts)
    || (value.max_install_attempts as number) < 1
  ) {
    return null;
  }
  if (value.scope === "global" ? value.scope_id !== null : typeof value.scope_id !== "string") {
    return null;
  }
  return {
    id: value.id,
    name: value.name,
    scope: value.scope as PatchScope,
    scope_id: value.scope_id as string | null,
    enabled: value.enabled,
    created_at: value.created_at,
    current_version: value.current_version as number,
    rule_count: value.rule_count as number,
    default_action: value.default_action as PatchDefaultAction,
    require_maintenance_window: value.require_maintenance_window,
    reboot_policy: value.reboot_policy as RebootPolicy,
    max_install_attempts: value.max_install_attempts as number,
  };
}

export function patchPolicyListFromUnknown(value: unknown): PatchApprovalPolicy[] | null {
  if (!Array.isArray(value)) return null;
  const policies = value.map(patchPolicyFromUnknown);
  return policies.every((policy): policy is PatchApprovalPolicy => policy !== null) ? policies : null;
}

export function patchPolicyDetailFromUnknown(value: unknown): PatchApprovalPolicyDetail | null {
  const policy = patchPolicyFromUnknown(value);
  if (policy === null || !isRecord(value)) return null;
  const rules = rulesFromUnknown(value.rules);
  if (rules === null) return null;
  if (!Array.isArray(value.revisions)) return null;
  const revisions: PatchApprovalPolicyRevision[] = [];
  for (const item of value.revisions) {
    if (!isRecord(item)) return null;
    const revisionRules = rulesFromUnknown(item.rules);
    if (
      typeof item.id !== "string"
      || !Number.isInteger(item.version)
      || !defaults.has(item.default_action as PatchDefaultAction)
      || typeof item.require_maintenance_window !== "boolean"
      || (item.change_note !== null && typeof item.change_note !== "string")
      || (item.created_by !== null && typeof item.created_by !== "string")
      || !isTimestamp(item.created_at)
      || revisionRules === null
    ) {
      return null;
    }
    revisions.push({
      id: item.id,
      version: item.version as number,
      default_action: item.default_action as PatchDefaultAction,
      require_maintenance_window: item.require_maintenance_window,
      change_note: (item.change_note as string | null) ?? null,
      created_by: (item.created_by as string | null) ?? null,
      created_at: item.created_at,
      rules: revisionRules,
    });
  }
  return { ...policy, rules, revisions };
}

export function effectivePatchPolicyFromUnknown(value: unknown): EffectivePatchPolicy | null {
  if (!isRecord(value)) return null;
  if (!Array.isArray(value.decisions)) return null;
  const decisions: PatchUpdateDecision[] = [];
  for (const item of value.decisions) {
    if (!isRecord(item)) return null;
    if (
      (item.kb_id !== null && typeof item.kb_id !== "string")
      || (item.update_id !== null && typeof item.update_id !== "string")
      || typeof item.title !== "string"
      || (item.classification !== null && typeof item.classification !== "string")
      || (item.severity !== null && typeof item.severity !== "string")
      || !actions.has(item.decision as PatchAction)
      || typeof item.reason !== "string"
      || (item.matched_rule_key !== null && item.matched_rule_key !== undefined && typeof item.matched_rule_key !== "string")
    ) {
      return null;
    }
    decisions.push({
      kb_id: (item.kb_id as string | null) ?? null,
      update_id: (item.update_id as string | null) ?? null,
      title: item.title,
      classification: (item.classification as string | null) ?? null,
      severity: (item.severity as string | null) ?? null,
      decision: item.decision as PatchAction,
      reason: item.reason,
      matched_rule_key: (item.matched_rule_key as string | null) ?? null,
    });
  }
  const scope = value.scope;
  const defaultAction = value.default_action;
  return {
    policy_id: typeof value.policy_id === "string" ? value.policy_id : null,
    policy_name: typeof value.policy_name === "string" ? value.policy_name : null,
    scope: scopes.has(scope as PatchScope) ? (scope as PatchScope) : null,
    default_action: defaults.has(defaultAction as PatchDefaultAction) ? (defaultAction as PatchDefaultAction) : null,
    require_maintenance_window: value.require_maintenance_window === true,
    decisions,
  };
}

export function formatPatchScope(scope: PatchScope): string {
  return { global: "Global", client: "Client", site: "Site", agent: "Endpoint" }[scope];
}

export function formatPatchAction(action: PatchAction): string {
  return { approve: "Approve", deny: "Deny", defer: "Defer" }[action];
}
