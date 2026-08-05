// SPDX-License-Identifier: AGPL-3.0-only

export type MonitoringScope = "global" | "client" | "site" | "agent";
export type CheckType = "offline" | "cpu" | "memory" | "disk" | "service" | "reboot_pending" | "uptime";
export type ThresholdOp = "gt" | "gte" | "lt" | "lte";

export type MonitoringCheck = {
  key: string;
  type: CheckType;
  enabled: boolean;
  schedule: { interval_seconds: number };
  threshold: {
    op: ThresholdOp;
    warning: number | null;
    critical: number | null;
  } | null;
  hysteresis: { raise_samples: number; clear_samples: number };
  params: Record<string, unknown>;
};

export type MonitoringPolicyRevision = {
  id: string;
  version: number;
  change_note: string | null;
  created_by: string | null;
  created_at: string;
  checks: MonitoringCheck[];
};

export type MonitoringPolicy = {
  id: string;
  name: string;
  scope: MonitoringScope;
  scope_id: string | null;
  enabled: boolean;
  created_at: string;
  current_version: number;
  check_count: number;
};

export type MonitoringPolicyDetail = MonitoringPolicy & {
  checks: MonitoringCheck[];
  revisions: MonitoringPolicyRevision[];
};

export type AlertState = "open" | "acknowledged" | "resolved";
export type AlertResultStatus = "ok" | "warning" | "critical" | "unknown";
export type AlertEventType =
  | "state_imported" | "opened" | "reopened" | "acknowledged" | "assigned"
  | "commented" | "manual_resolution" | "automatic_recovery"
  | "policy_revised" | "policy_deleted" | "policy_superseded";

export type MonitoringAlert = {
  id: string;
  agent_id: string;
  policy_id: string;
  policy_revision_id: string;
  check_key: string;
  state: AlertState;
  last_result_status: AlertResultStatus;
  occurrence_count: number;
  total_occurrence_count: number;
  generation: number;
  first_opened_at: string | null;
  opened_at: string | null;
  last_observed_at: string | null;
  resolved_at: string | null;
  last_evaluated_at: string | null;
  last_result_id: string | null;
  last_value: number | null;
  resolution_reason: string | null;
  suppression_window_id: string | null;
  suppressed_until: string | null;
  assigned_to_operator_id: string | null;
  assigned_to_email: string | null;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
  version: number;
  created_at: string;
  updated_at: string;
};

export type AlertEvent = {
  id: string;
  alert_id: string;
  generation: number;
  event_type: AlertEventType;
  from_state: AlertState | null;
  to_state: AlertState | null;
  actor: string;
  actor_user_id: string | null;
  comment: string | null;
  comment_redacted: boolean;
  assigned_to_operator_id: string | null;
  assigned_to_email: string | null;
  source_result_id: string | null;
  request_id: string | null;
  created_at: string;
};

export type AlertObservation = {
  check_result_id: string;
  alert_id: string;
  status: AlertResultStatus;
  value: number | null;
  evaluated_at: string;
  out_of_order: boolean;
  created_at: string;
};

export type MonitoringAlertDetail = MonitoringAlert & {
  events: AlertEvent[];
  observations: AlertObservation[];
};

export type AlertAssignee = { id: string; email: string };
export type AlertActionInput = {
  request_id: string;
  expected_version: number;
  comment?: string;
  assigned_to_operator_id?: string | null;
};

export type AlertEmailDeliveryStatus = "pending" | "sending" | "retrying" | "sent" | "failed" | "suppressed";
export type AlertEmailAttemptStatus = "sending" | "sent" | "retrying" | "failed";
export type AlertEmailAttempt = {
  id: string;
  attempt_number: number;
  status: AlertEmailAttemptStatus;
  provider_message_id: string | null;
  error_code: string | null;
  created_at: string;
  completed_at: string | null;
};
export type AlertEmailDelivery = {
  id: string;
  alert_id: string;
  alert_event_id: string;
  generation: number;
  event_type: AlertEventType;
  recipient: string;
  status: AlertEmailDeliveryStatus;
  attempt_count: number;
  max_attempts: number;
  next_attempt_at: string;
  provider_message_id: string | null;
  last_error_code: string | null;
  sent_at: string | null;
  created_at: string;
  updated_at: string;
  attempts: AlertEmailAttempt[];
};

const scopes = new Set<MonitoringScope>(["global", "client", "site", "agent"]);
const checkTypes = new Set<CheckType>([
  "offline",
  "cpu",
  "memory",
  "disk",
  "service",
  "reboot_pending",
  "uptime",
]);
const thresholdOps = new Set<ThresholdOp>(["gt", "gte", "lt", "lte"]);
const alertStates = new Set<AlertState>(["open", "acknowledged", "resolved"]);
const alertStatuses = new Set<AlertResultStatus>(["ok", "warning", "critical", "unknown"]);
const alertEventTypes = new Set<AlertEventType>([
  "state_imported", "opened", "reopened", "acknowledged", "assigned", "commented",
  "manual_resolution", "automatic_recovery", "policy_revised", "policy_deleted",
  "policy_superseded",
]);
const emailDeliveryStatuses = new Set<AlertEmailDeliveryStatus>([
  "pending", "sending", "retrying", "sent", "failed", "suppressed",
]);
const emailAttemptStatuses = new Set<AlertEmailAttemptStatus>([
  "sending", "sent", "retrying", "failed",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isTimestamp(value: unknown): value is string {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

function checkFromUnknown(value: unknown): MonitoringCheck | null {
  if (!isRecord(value) || !isRecord(value.schedule) || !isRecord(value.hysteresis)) return null;
  const threshold = value.threshold;
  if (
    typeof value.key !== "string"
    || !checkTypes.has(value.type as CheckType)
    || typeof value.enabled !== "boolean"
    || typeof value.schedule.interval_seconds !== "number"
    || typeof value.hysteresis.raise_samples !== "number"
    || typeof value.hysteresis.clear_samples !== "number"
    || !isRecord(value.params)
  ) {
    return null;
  }
  let normalizedThreshold: MonitoringCheck["threshold"] = null;
  if (threshold !== null) {
    if (
      !isRecord(threshold)
      || !thresholdOps.has(threshold.op as ThresholdOp)
      || (threshold.warning !== null && typeof threshold.warning !== "number")
      || (threshold.critical !== null && typeof threshold.critical !== "number")
    ) {
      return null;
    }
    normalizedThreshold = {
      op: threshold.op as ThresholdOp,
      warning: threshold.warning as number | null,
      critical: threshold.critical as number | null,
    };
  }
  return {
    key: value.key,
    type: value.type as CheckType,
    enabled: value.enabled,
    schedule: { interval_seconds: value.schedule.interval_seconds },
    threshold: normalizedThreshold,
    hysteresis: {
      raise_samples: value.hysteresis.raise_samples,
      clear_samples: value.hysteresis.clear_samples,
    },
    params: { ...value.params },
  };
}

function checksFromUnknown(value: unknown): MonitoringCheck[] | null {
  if (!Array.isArray(value)) return null;
  const checks = value.map(checkFromUnknown);
  return checks.every((check): check is MonitoringCheck => check !== null) ? checks : null;
}

export function monitoringPolicyFromUnknown(value: unknown): MonitoringPolicy | null {
  if (!isRecord(value)) return null;
  if (
    typeof value.id !== "string"
    || typeof value.name !== "string"
    || !scopes.has(value.scope as MonitoringScope)
    || (value.scope_id !== null && typeof value.scope_id !== "string")
    || typeof value.enabled !== "boolean"
    || !isTimestamp(value.created_at)
    || !Number.isInteger(value.current_version)
    || !Number.isInteger(value.check_count)
    || (value.current_version as number) < 0
    || (value.check_count as number) < 0
  ) {
    return null;
  }
  if (value.scope === "global" ? value.scope_id !== null : typeof value.scope_id !== "string") {
    return null;
  }
  return {
    id: value.id,
    name: value.name,
    scope: value.scope as MonitoringScope,
    scope_id: value.scope_id as string | null,
    enabled: value.enabled,
    created_at: value.created_at,
    current_version: value.current_version as number,
    check_count: value.check_count as number,
  };
}

export function monitoringPolicyListFromUnknown(value: unknown): MonitoringPolicy[] | null {
  if (!Array.isArray(value)) return null;
  const policies = value.map(monitoringPolicyFromUnknown);
  return policies.every((policy): policy is MonitoringPolicy => policy !== null)
    ? policies
    : null;
}

export function monitoringPolicyDetailFromUnknown(value: unknown): MonitoringPolicyDetail | null {
  const policy = monitoringPolicyFromUnknown(value);
  if (!policy || !isRecord(value)) return null;
  const checks = checksFromUnknown(value.checks);
  if (!checks || !Array.isArray(value.revisions)) return null;
  const revisions = value.revisions.map((item): MonitoringPolicyRevision | null => {
    if (!isRecord(item)) return null;
    const revisionChecks = checksFromUnknown(item.checks);
    if (
      typeof item.id !== "string"
      || !Number.isInteger(item.version)
      || (item.change_note !== null && typeof item.change_note !== "string")
      || (item.created_by !== null && typeof item.created_by !== "string")
      || !isTimestamp(item.created_at)
      || !revisionChecks
    ) {
      return null;
    }
    return {
      id: item.id,
      version: item.version as number,
      change_note: item.change_note as string | null,
      created_by: item.created_by as string | null,
      created_at: item.created_at,
      checks: revisionChecks,
    };
  });
  if (!revisions.every((revision): revision is MonitoringPolicyRevision => revision !== null)) {
    return null;
  }
  return { ...policy, checks, revisions };
}

function nullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function nullableTimestamp(value: unknown): value is string | null {
  return value === null || isTimestamp(value);
}

export function monitoringAlertFromUnknown(value: unknown): MonitoringAlert | null {
  if (!isRecord(value)) return null;
  const timestampFields = [
    "first_opened_at", "opened_at", "last_observed_at", "resolved_at",
    "last_evaluated_at", "suppressed_until", "acknowledged_at",
  ];
  const stringFields = [
    "last_result_id", "resolution_reason", "suppression_window_id",
    "assigned_to_operator_id", "assigned_to_email", "acknowledged_by",
  ];
  if (
    typeof value.id !== "string" || typeof value.agent_id !== "string"
    || typeof value.policy_id !== "string" || typeof value.policy_revision_id !== "string"
    || typeof value.check_key !== "string" || !alertStates.has(value.state as AlertState)
    || !alertStatuses.has(value.last_result_status as AlertResultStatus)
    || !["occurrence_count", "total_occurrence_count", "generation", "version"].every(
      (key) => Number.isInteger(value[key]) && (value[key] as number) >= (key === "version" ? 1 : 0),
    )
    || !timestampFields.every((key) => nullableTimestamp(value[key]))
    || !stringFields.every((key) => nullableString(value[key]))
    || (value.last_value !== null && typeof value.last_value !== "number")
    || !isTimestamp(value.created_at) || !isTimestamp(value.updated_at)
  ) return null;
  return {
    id: value.id, agent_id: value.agent_id, policy_id: value.policy_id,
    policy_revision_id: value.policy_revision_id, check_key: value.check_key,
    state: value.state as AlertState,
    last_result_status: value.last_result_status as AlertResultStatus,
    occurrence_count: value.occurrence_count as number,
    total_occurrence_count: value.total_occurrence_count as number,
    generation: value.generation as number,
    first_opened_at: value.first_opened_at as string | null,
    opened_at: value.opened_at as string | null,
    last_observed_at: value.last_observed_at as string | null,
    resolved_at: value.resolved_at as string | null,
    last_evaluated_at: value.last_evaluated_at as string | null,
    last_result_id: value.last_result_id as string | null,
    last_value: value.last_value as number | null,
    resolution_reason: value.resolution_reason as string | null,
    suppression_window_id: value.suppression_window_id as string | null,
    suppressed_until: value.suppressed_until as string | null,
    assigned_to_operator_id: value.assigned_to_operator_id as string | null,
    assigned_to_email: value.assigned_to_email as string | null,
    acknowledged_at: value.acknowledged_at as string | null,
    acknowledged_by: value.acknowledged_by as string | null,
    version: value.version as number,
    created_at: value.created_at as string, updated_at: value.updated_at as string,
  };
}

function alertEventFromUnknown(value: unknown): AlertEvent | null {
  if (!isRecord(value)) return null;
  if (
    typeof value.id !== "string" || typeof value.alert_id !== "string"
    || !Number.isInteger(value.generation) || (value.generation as number) < 0
    || !alertEventTypes.has(value.event_type as AlertEventType)
    || !(value.from_state === null || alertStates.has(value.from_state as AlertState))
    || !(value.to_state === null || alertStates.has(value.to_state as AlertState))
    || typeof value.actor !== "string" || !nullableString(value.actor_user_id)
    || !nullableString(value.comment) || typeof value.comment_redacted !== "boolean"
    || !nullableString(value.assigned_to_operator_id) || !nullableString(value.assigned_to_email)
    || !nullableString(value.source_result_id) || !nullableString(value.request_id)
    || !isTimestamp(value.created_at)
  ) return null;
  return {
    id: value.id, alert_id: value.alert_id, generation: value.generation as number,
    event_type: value.event_type as AlertEventType,
    from_state: value.from_state as AlertState | null,
    to_state: value.to_state as AlertState | null,
    actor: value.actor, actor_user_id: value.actor_user_id as string | null,
    comment: value.comment as string | null, comment_redacted: value.comment_redacted,
    assigned_to_operator_id: value.assigned_to_operator_id as string | null,
    assigned_to_email: value.assigned_to_email as string | null,
    source_result_id: value.source_result_id as string | null,
    request_id: value.request_id as string | null, created_at: value.created_at,
  };
}

function alertObservationFromUnknown(value: unknown): AlertObservation | null {
  if (!isRecord(value)) return null;
  if (
    typeof value.check_result_id !== "string" || typeof value.alert_id !== "string"
    || !alertStatuses.has(value.status as AlertResultStatus)
    || (value.value !== null && typeof value.value !== "number")
    || !isTimestamp(value.evaluated_at) || typeof value.out_of_order !== "boolean"
    || !isTimestamp(value.created_at)
  ) return null;
  return {
    check_result_id: value.check_result_id, alert_id: value.alert_id,
    status: value.status as AlertResultStatus, value: value.value as number | null,
    evaluated_at: value.evaluated_at, out_of_order: value.out_of_order,
    created_at: value.created_at,
  };
}

export function monitoringAlertListFromUnknown(value: unknown): MonitoringAlert[] | null {
  if (!isRecord(value) || !Array.isArray(value.items)) return null;
  const items = value.items.map(monitoringAlertFromUnknown);
  return items.every((item): item is MonitoringAlert => item !== null) ? items : null;
}

export function monitoringAlertDetailFromUnknown(value: unknown): MonitoringAlertDetail | null {
  const alert = monitoringAlertFromUnknown(value);
  if (!alert || !isRecord(value) || !Array.isArray(value.events) || !Array.isArray(value.observations)) return null;
  const events = value.events.map(alertEventFromUnknown);
  const observations = value.observations.map(alertObservationFromUnknown);
  if (!events.every((item): item is AlertEvent => item !== null)
      || !observations.every((item): item is AlertObservation => item !== null)) return null;
  return { ...alert, events, observations };
}

export function alertAssigneesFromUnknown(value: unknown): AlertAssignee[] | null {
  if (!Array.isArray(value)) return null;
  const items = value.map((item): AlertAssignee | null =>
    isRecord(item) && typeof item.id === "string" && typeof item.email === "string"
      ? { id: item.id, email: item.email } : null,
  );
  return items.every((item): item is AlertAssignee => item !== null) ? items : null;
}

export function validateAlertActionInput(value: unknown): AlertActionInput | null {
  if (!isRecord(value) || typeof value.request_id !== "string"
      || !/^[A-Za-z0-9_-]{16,64}$/.test(value.request_id)
      || !Number.isInteger(value.expected_version) || (value.expected_version as number) < 1
      || !(value.comment === undefined || (typeof value.comment === "string" && value.comment.trim().length <= 2000))
      || !(value.assigned_to_operator_id === undefined || value.assigned_to_operator_id === null || typeof value.assigned_to_operator_id === "string")) return null;
  return {
    request_id: value.request_id,
    expected_version: value.expected_version as number,
    ...(typeof value.comment === "string" ? { comment: value.comment.trim() } : {}),
    ...(value.assigned_to_operator_id !== undefined
      ? { assigned_to_operator_id: value.assigned_to_operator_id as string | null } : {}),
  };
}

function alertEmailAttemptFromUnknown(value: unknown): AlertEmailAttempt | null {
  if (!isRecord(value) || typeof value.id !== "string"
      || !Number.isInteger(value.attempt_number) || (value.attempt_number as number) < 1
      || !emailAttemptStatuses.has(value.status as AlertEmailAttemptStatus)
      || !nullableString(value.provider_message_id) || !nullableString(value.error_code)
      || !isTimestamp(value.created_at)
      || !(value.completed_at === null || isTimestamp(value.completed_at))) return null;
  return {
    id: value.id, attempt_number: value.attempt_number as number,
    status: value.status as AlertEmailAttemptStatus,
    provider_message_id: value.provider_message_id as string | null,
    error_code: value.error_code as string | null, created_at: value.created_at,
    completed_at: value.completed_at as string | null,
  };
}

function parseAlertEmailDelivery(value: unknown): AlertEmailDelivery | null {
  if (!isRecord(value) || typeof value.id !== "string" || typeof value.alert_id !== "string"
      || typeof value.alert_event_id !== "string" || typeof value.recipient !== "string"
      || !Number.isInteger(value.generation) || (value.generation as number) < 0
      || !alertEventTypes.has(value.event_type as AlertEventType)
      || !emailDeliveryStatuses.has(value.status as AlertEmailDeliveryStatus)
      || !Number.isInteger(value.attempt_count) || (value.attempt_count as number) < 0
      || !Number.isInteger(value.max_attempts) || (value.max_attempts as number) < 1
      || !isTimestamp(value.next_attempt_at) || !nullableString(value.provider_message_id)
      || !nullableString(value.last_error_code)
      || !(value.sent_at === null || isTimestamp(value.sent_at))
      || !isTimestamp(value.created_at) || !isTimestamp(value.updated_at)
      || !Array.isArray(value.attempts)) return null;
  const attempts = value.attempts.map(alertEmailAttemptFromUnknown);
  if (!attempts.every((item): item is AlertEmailAttempt => item !== null)) return null;
  return {
    id: value.id, alert_id: value.alert_id, alert_event_id: value.alert_event_id,
    generation: value.generation as number, event_type: value.event_type as AlertEventType,
    recipient: value.recipient, status: value.status as AlertEmailDeliveryStatus,
    attempt_count: value.attempt_count as number, max_attempts: value.max_attempts as number,
    next_attempt_at: value.next_attempt_at,
    provider_message_id: value.provider_message_id as string | null,
    last_error_code: value.last_error_code as string | null,
    sent_at: value.sent_at as string | null, created_at: value.created_at,
    updated_at: value.updated_at, attempts,
  };
}

export function alertEmailDeliveryFromUnknown(value: unknown): AlertEmailDelivery | null {
  return parseAlertEmailDelivery(value);
}

export function alertEmailDeliveryListFromUnknown(value: unknown): AlertEmailDelivery[] | null {
  if (!isRecord(value) || !Array.isArray(value.items)) return null;
  const items = value.items.map(parseAlertEmailDelivery);
  return items.every((item): item is AlertEmailDelivery => item !== null) ? items : null;
}

export function formatAlertEventType(type: AlertEventType): string {
  return type.replaceAll("_", " ");
}

export function formatMonitoringScope(scope: MonitoringScope): string {
  return {
    global: "Global",
    client: "Client",
    site: "Site",
    agent: "Agent",
  }[scope];
}

export function formatMonitoringTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unavailable";
  return `${new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(date)} UTC`;
}

export function formatCheckInterval(seconds: number): string {
  if (seconds % 3600 === 0) return `Every ${seconds / 3600}h`;
  if (seconds % 60 === 0) return `Every ${seconds / 60}m`;
  return `Every ${seconds}s`;
}

export function describeThreshold(threshold: MonitoringCheck["threshold"]): string {
  if (!threshold) return "State check";
  const operator = { gt: ">", gte: "â‰¥", lt: "<", lte: "â‰¤" }[threshold.op];
  return [
    threshold.warning === null ? null : `Warning ${operator} ${threshold.warning}`,
    threshold.critical === null ? null : `Critical ${operator} ${threshold.critical}`,
  ].filter(Boolean).join(" Â· ");
}

export function formatCheckType(type: CheckType): string {
  return type.replaceAll("_", " ");
}
