// SPDX-License-Identifier: AGPL-3.0-only

/** Justified emergency override presentation and validation (issue #65).
 *
 * The management service decides everything that matters: whether the policy
 * allows an override, whether the activator is a tenant admin who could run
 * the command anyway, whether the override is still live, who may review it.
 * This module exists so the page can show the same answer before a click and
 * so a malformed response can never reach the UI; every parser fails closed.
 *
 * The `can*` helpers are hints that hide controls the server would refuse.
 * The server refusing them is what makes the control real.
 */

export type OverrideStatus = "active" | "consumed" | "expired" | "revoked";

export type EmergencyOverride = {
  id: string;
  agent_id: string;
  client_id: string | null;
  site_id: string | null;
  kind: string;
  status: OverrideStatus;
  payload_sha256: string;
  policy_id: string | null;
  required_approvals: number;
  activated_by_email: string;
  activated_by_operator_id: string | null;
  justification: string;
  created_at: string;
  expires_at: string;
  consumed_at: string | null;
  revoked_at: string | null;
  revoked_by_email: string | null;
  notified_at: string | null;
  notification_error: string | null;
  notified_recipient_count: number;
  reviewed_at: string | null;
  reviewed_by_email: string | null;
};

export type EmergencyOverrideDetail = EmergencyOverride & {
  payload: Record<string, unknown>;
  payload_keys: string[];
  revoke_reason: string | null;
  review_note: string | null;
  consumed_command_id: string | null;
};

export const MIN_JUSTIFICATION_BYTES = 20;
export const MAX_JUSTIFICATION_BYTES = 512;
export const MIN_NOTE_BYTES = 10;
export const MAX_NOTE_BYTES = 512;
export const MIN_TTL_SECONDS = 60;
export const MAX_TTL_SECONDS = 3600;
export const DEFAULT_TTL_SECONDS = 900;

/** Kinds an administrator may bind an override to. Mirrors the service's
 * CommandKind vocabulary minus the lifecycle markers it never dispatches. */
export const OVERRIDE_COMMAND_KINDS = [
  "powershell",
  "shell",
  "collect_inventory",
  "scan_updates",
  "install_updates",
  "file_upload",
  "file_download",
  "registry_read",
  "registry_write",
  "registry_delete",
  "remediation_rollback",
  "reboot",
  "shutdown",
  "cancel_power_action",
  "query_event_log",
  "scan_packages",
  "install_packages",
  "deploy_software",
  "list_services",
  "control_service",
  "list_processes",
  "terminate_process",
  "agent_self_update",
  "agent_update_rollback",
] as const;

const STATUSES: OverrideStatus[] = ["active", "consumed", "expired", "revoked"];

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

export function emergencyOverrideFromUnknown(value: unknown): EmergencyOverride | null {
  if (!isRecord(value)) return null;
  const { id, agent_id: agentId, kind, status } = value;
  if (typeof id !== "string" || !id) return null;
  if (typeof agentId !== "string" || !agentId) return null;
  if (typeof kind !== "string" || !kind) return null;
  if (typeof status !== "string" || !STATUSES.includes(status as OverrideStatus)) return null;
  if (typeof value.payload_sha256 !== "string") return null;
  const required = value.required_approvals;
  const recipients = value.notified_recipient_count;
  if (typeof required !== "number" || !Number.isInteger(required)) return null;
  if (typeof recipients !== "number" || !Number.isInteger(recipients)) return null;
  if (typeof value.activated_by_email !== "string") return null;
  if (typeof value.justification !== "string") return null;
  if (typeof value.created_at !== "string") return null;
  if (typeof value.expires_at !== "string") return null;
  const optional = {
    client_id: stringOrNull(value.client_id),
    site_id: stringOrNull(value.site_id),
    policy_id: stringOrNull(value.policy_id),
    activated_by_operator_id: stringOrNull(value.activated_by_operator_id),
    consumed_at: stringOrNull(value.consumed_at),
    revoked_at: stringOrNull(value.revoked_at),
    revoked_by_email: stringOrNull(value.revoked_by_email),
    notified_at: stringOrNull(value.notified_at),
    notification_error: stringOrNull(value.notification_error),
    reviewed_at: stringOrNull(value.reviewed_at),
    reviewed_by_email: stringOrNull(value.reviewed_by_email),
  };
  if (Object.values(optional).some((entry) => entry === undefined)) return null;
  return {
    id,
    agent_id: agentId,
    kind,
    status: status as OverrideStatus,
    payload_sha256: value.payload_sha256,
    required_approvals: required,
    activated_by_email: value.activated_by_email,
    justification: value.justification,
    created_at: value.created_at,
    expires_at: value.expires_at,
    notified_recipient_count: recipients,
    ...(optional as {
      [K in keyof typeof optional]: string | null;
    }),
  };
}

export function emergencyOverrideListFromUnknown(value: unknown): EmergencyOverride[] | null {
  if (!Array.isArray(value)) return null;
  const parsed = value.map(emergencyOverrideFromUnknown);
  return parsed.every((entry): entry is EmergencyOverride => entry !== null) ? parsed : null;
}

export function emergencyOverrideDetailFromUnknown(
  value: unknown,
): EmergencyOverrideDetail | null {
  const summary = emergencyOverrideFromUnknown(value);
  if (!summary || !isRecord(value)) return null;
  if (!isRecord(value.payload)) return null;
  const keys = stringList(value.payload_keys);
  if (!keys) return null;
  const revokeReason = stringOrNull(value.revoke_reason);
  const reviewNote = stringOrNull(value.review_note);
  const commandId = stringOrNull(value.consumed_command_id);
  if (revokeReason === undefined || reviewNote === undefined || commandId === undefined) {
    return null;
  }
  return {
    ...summary,
    payload: value.payload,
    payload_keys: keys,
    revoke_reason: revokeReason,
    review_note: reviewNote,
    consumed_command_id: commandId,
  };
}

function isPrintableProse(text: string, min: number, max: number): boolean {
  const trimmed = text.trim();
  const size = new TextEncoder().encode(trimmed).length;
  if (size < min || size > max) return false;
  return ![...trimmed].some((char) => {
    const code = char.codePointAt(0) ?? 0;
    return code < 32 || code === 127;
  });
}

export function isValidJustification(text: string): boolean {
  return isPrintableProse(text, MIN_JUSTIFICATION_BYTES, MAX_JUSTIFICATION_BYTES);
}

export function isValidNote(text: string): boolean {
  return isPrintableProse(text, MIN_NOTE_BYTES, MAX_NOTE_BYTES);
}

export function isValidTtlSeconds(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    value >= MIN_TTL_SECONDS &&
    value <= MAX_TTL_SECONDS
  );
}

/** Parse the operator's payload text. Must be a JSON object; anything else
 * (an array, a scalar, invalid JSON) is refused before it leaves the browser. */
export function parsePayloadText(text: string): Record<string, unknown> | null {
  const trimmed = text.trim();
  if (trimmed === "") return {};
  try {
    const parsed: unknown = JSON.parse(trimmed);
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export function isLive(override: EmergencyOverride, now: Date): boolean {
  return override.status === "active" && Date.parse(override.expires_at) > now.getTime();
}

/** The activator may run the bound command while the override is live. */
export function canRun(
  override: EmergencyOverride,
  viewerOperatorId: string | null,
  now: Date,
): boolean {
  return (
    !!viewerOperatorId &&
    override.activated_by_operator_id === viewerOperatorId &&
    isLive(override, now)
  );
}

/** The activator or an admin may withdraw a live override. */
export function canRevoke(
  override: EmergencyOverride,
  viewerOperatorId: string | null,
  viewerIsAdmin: boolean,
  now: Date,
): boolean {
  if (!isLive(override, now)) return false;
  if (viewerIsAdmin) return true;
  return !!viewerOperatorId && override.activated_by_operator_id === viewerOperatorId;
}

/** An admin other than the activator may sign off, once. */
export function canReview(
  override: EmergencyOverride,
  viewerOperatorId: string | null,
  viewerIsAdmin: boolean,
): boolean {
  if (override.reviewed_at !== null) return false;
  if (!viewerIsAdmin || !viewerOperatorId) return false;
  return override.activated_by_operator_id !== viewerOperatorId;
}

export function statusLabel(status: OverrideStatus): string {
  switch (status) {
    case "active":
      return "Active";
    case "consumed":
      return "Executed";
    case "expired":
      return "Expired";
    case "revoked":
      return "Revoked";
  }
}

export function notificationLabel(override: EmergencyOverride): string {
  if (override.notified_at) {
    const count = override.notified_recipient_count;
    return `notified ${count} ${count === 1 ? "recipient" : "recipients"}`;
  }
  switch (override.notification_error) {
    case "no_recipients_configured":
      return "nobody notified: no alert recipients configured";
    case "email_provider_unavailable":
      return "nobody notified: email provider unavailable";
    case null:
      return "notification pending";
    default:
      return `nobody notified: ${override.notification_error}`;
  }
}

/** Unreviewed first, then live, then newest. The queue is a list of debts. */
export function sortForReview<T extends EmergencyOverride>(rows: T[]): T[] {
  const rank = (row: T): number => {
    if (row.reviewed_at === null && row.status !== "active") return 0;
    if (row.status === "active") return 1;
    return 2;
  };
  return [...rows].sort((left, right) => {
    if (rank(left) !== rank(right)) return rank(left) - rank(right);
    return Date.parse(right.created_at) - Date.parse(left.created_at);
  });
}

export function formatTimeRemaining(expiresAt: string, now: Date): string {
  const remaining = Date.parse(expiresAt) - now.getTime();
  if (Number.isNaN(remaining)) return "unknown";
  if (remaining <= 0) return "expired";
  const minutes = Math.floor(remaining / 60_000);
  if (minutes < 1) return "under a minute left";
  if (minutes < 60) return `${minutes} min left`;
  return `${Math.floor(minutes / 60)} h ${minutes % 60} min left`;
}

/** Refusal codes, phrased for the person who just clicked. */
export const OVERRIDE_MESSAGES: Record<string, string> = {
  emergency_override_not_required:
    "No approval policy governs this command on this endpoint, so there is nothing to override.",
  emergency_override_not_permitted:
    "The approval policy for this command does not allow emergency overrides.",
  emergency_override_role_insufficient:
    "Only a tenant administrator or platform administrator can activate an override.",
  emergency_override_tenant_not_visible: "You do not have access to this endpoint's client.",
  emergency_override_operator_disabled: "Your account cannot activate overrides.",
  emergency_override_limit_reached:
    "You already hold the maximum number of open overrides for this client. Revoke or use one first.",
  emergency_override_not_found: "This override no longer exists.",
  emergency_override_already_consumed: "This override has already been used.",
  emergency_override_expired: "This override has expired. Activate a new one if still needed.",
  emergency_override_revoked: "This override was revoked.",
  emergency_override_not_active: "This override is no longer active.",
  emergency_override_payload_mismatch:
    "The command no longer matches what the override was bound to.",
  emergency_override_activator_mismatch: "Only the person who activated an override can use it.",
  emergency_override_activator_no_longer_eligible:
    "Your authority to override has lapsed since activation (role, policy, or script grant changed).",
  emergency_override_self_review_not_permitted: "You activated this override, so you cannot review it.",
  emergency_override_review_not_permitted:
    "Only a tenant administrator or platform administrator can review an override.",
  emergency_override_already_reviewed: "This override has already been reviewed.",
  emergency_override_revoke_not_permitted:
    "Only the activator or a tenant administrator can revoke this override.",
  approval_and_override_both_cited: "Cite an approval or an override, not both.",
  command_payload_invalid: "The payload is not a valid command payload.",
  command_payload_too_large: "The payload is too large.",
  agent_not_found: "This endpoint no longer exists or is not visible to you.",
  step_up_required: "Confirm your security key or authenticator before activating an override.",
};
