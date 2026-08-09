// SPDX-License-Identifier: AGPL-3.0-only

// Command kind/status unions are duplicated from command-console-core rather
// than imported: this module is loaded directly by the node:test runner, which
// does not resolve the "@/" path alias. They are structurally identical to the
// command-console definitions, so values flow between the two without casts.
export type CommandKind =
  | "powershell"
  | "shell"
  | "collect_inventory"
  | "scan_updates"
  | "install_updates"
  | "file_upload"
  | "file_download"
  | "registry_read"
  | "registry_write"
  | "registry_delete"
  | "remediation_rollback";

export type CommandStatus =
  | "queued"
  | "dispatched"
  | "running"
  | "result_pending"
  | "succeeded"
  | "failed"
  | "expired";

// The complete cross-endpoint task-run history (issue #50). A run is a command
// row plus the provenance recorded at dispatch and the endpoint hostname. Like
// the per-endpoint history this is metadata only — captured stdout/stderr stay
// behind the audited command-detail read and never appear here.
export type TaskRunItem = {
  id: string;
  agent_id: string;
  hostname: string | null;
  kind: CommandKind;
  status: CommandStatus;
  envelope_version: string;
  schema_version: number | null;
  signing_key_id: string | null;
  exit_code: number | null;
  stdout_truncated: boolean | null;
  stderr_truncated: boolean | null;
  created_at: string;
  issued_at: string | null;
  dispatched_at: string | null;
  agent_completed_at: string | null;
  completed_at: string | null;
  expires_at: string | null;
  actor_email: string | null;
  actor_operator_id: string | null;
  script_version_id: string | null;
  script_parameter_value_set_id: string | null;
  dispatch_audit_event_id: string | null;
  planned_at: string | null;
  attempt: number;
  parent_command_id: string | null;
};

export type TaskRunHistoryData = {
  items: TaskRunItem[];
  page: number;
  page_size: number;
  total: number;
};

export type TaskRunFilters = {
  agentId?: string;
  status?: CommandStatus;
  kind?: CommandKind;
  from?: string;
  to?: string;
};

const commandKinds = new Set<CommandKind>([
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
]);

const commandStatuses = new Set<CommandStatus>([
  "queued",
  "dispatched",
  "running",
  "result_pending",
  "succeeded",
  "failed",
  "expired",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function nullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function nullableNumber(value: unknown): value is number | null {
  return value === null || typeof value === "number";
}

function nullableBoolean(value: unknown): value is boolean | null {
  return value === null || typeof value === "boolean";
}

/** Narrow a supplied string to a known command status, or undefined. */
export function asCommandStatus(value: unknown): CommandStatus | undefined {
  return commandStatuses.has(value as CommandStatus)
    ? (value as CommandStatus)
    : undefined;
}

/** Narrow a supplied string to a known command kind, or undefined. */
export function asCommandKind(value: unknown): CommandKind | undefined {
  return commandKinds.has(value as CommandKind)
    ? (value as CommandKind)
    : undefined;
}

export function taskRunItemFromUnknown(value: unknown): TaskRunItem | null {
  if (!isRecord(value)) return null;
  const nullableStringFields = [
    "signing_key_id",
    "issued_at",
    "dispatched_at",
    "agent_completed_at",
    "completed_at",
    "expires_at",
    "hostname",
    "actor_email",
    "actor_operator_id",
    "script_version_id",
    "script_parameter_value_set_id",
    "dispatch_audit_event_id",
    "planned_at",
    "parent_command_id",
  ];
  if (
    !isNonEmptyString(value.id)
    || !isNonEmptyString(value.agent_id)
    || !commandKinds.has(value.kind as CommandKind)
    || !commandStatuses.has(value.status as CommandStatus)
    || !isNonEmptyString(value.envelope_version)
    || !nullableNumber(value.schema_version)
    || !nullableNumber(value.exit_code)
    || !nullableBoolean(value.stdout_truncated)
    || !nullableBoolean(value.stderr_truncated)
    || !isNonEmptyString(value.created_at)
    || !Number.isInteger(value.attempt)
    || (value.attempt as number) < 1
    || !nullableStringFields.every((key) => nullableString(value[key]))
  ) {
    return null;
  }
  return {
    id: value.id,
    agent_id: value.agent_id,
    hostname: value.hostname as string | null,
    kind: value.kind as CommandKind,
    status: value.status as CommandStatus,
    envelope_version: value.envelope_version,
    schema_version: value.schema_version as number | null,
    signing_key_id: value.signing_key_id as string | null,
    exit_code: value.exit_code as number | null,
    stdout_truncated: value.stdout_truncated as boolean | null,
    stderr_truncated: value.stderr_truncated as boolean | null,
    created_at: value.created_at,
    issued_at: value.issued_at as string | null,
    dispatched_at: value.dispatched_at as string | null,
    agent_completed_at: value.agent_completed_at as string | null,
    completed_at: value.completed_at as string | null,
    expires_at: value.expires_at as string | null,
    actor_email: value.actor_email as string | null,
    actor_operator_id: value.actor_operator_id as string | null,
    script_version_id: value.script_version_id as string | null,
    script_parameter_value_set_id: value.script_parameter_value_set_id as string | null,
    dispatch_audit_event_id: value.dispatch_audit_event_id as string | null,
    planned_at: value.planned_at as string | null,
    attempt: value.attempt as number,
    parent_command_id: value.parent_command_id as string | null,
  };
}

export function taskRunHistoryFromUnknown(value: unknown): TaskRunHistoryData | null {
  if (
    !isRecord(value)
    || !Array.isArray(value.items)
    || !Number.isInteger(value.page)
    || !Number.isInteger(value.page_size)
    || !Number.isInteger(value.total)
  ) {
    return null;
  }
  const items = value.items.map(taskRunItemFromUnknown);
  if (!items.every((item): item is TaskRunItem => item !== null)) return null;
  return {
    items,
    page: value.page as number,
    page_size: value.page_size as number,
    total: value.total as number,
  };
}

export function taskRunPageCount(total: number, pageSize: number): number {
  return Math.max(1, Math.ceil(total / pageSize));
}

export function formatTaskRunTimestamp(value: string | null): string {
  if (value === null) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unavailable";
  return `${new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(date)} UTC`;
}

/** Build a /tasks href that preserves the active filters for a target page. */
export function taskRunPageHref(
  filters: TaskRunFilters,
  page: number,
): string {
  const query = new URLSearchParams();
  if (filters.agentId) query.set("agent_id", filters.agentId);
  if (filters.status) query.set("status", filters.status);
  if (filters.kind) query.set("kind", filters.kind);
  if (filters.from) query.set("from", filters.from);
  if (filters.to) query.set("to", filters.to);
  if (page > 1) query.set("page", String(page));
  const suffix = query.toString();
  return suffix ? `/tasks?${suffix}` : "/tasks";
}

export function hasTaskRunFilters(filters: TaskRunFilters): boolean {
  return Boolean(
    filters.agentId || filters.status || filters.kind || filters.from || filters.to,
  );
}
