// SPDX-License-Identifier: AGPL-3.0-only

export type ScheduledTaskTargetType = "agent" | "site";
export type ScheduledConcurrencyPolicy = "skip" | "queue" | "allow";
export type ScheduledMisfirePolicy = "run_once" | "skip";

export type ScheduledTaskItem = {
  id: string;
  name: string;
  description: string | null;
  enabled: boolean;
  target_type: ScheduledTaskTargetType;
  target_id: string;
  cron_expression: string;
  timezone: string;
  kind: string;
  script_version_id: string | null;
  payload: Record<string, unknown>;
  concurrency_policy: ScheduledConcurrencyPolicy;
  misfire_policy: ScheduledMisfirePolicy;
  next_run_at: string;
  last_run_at: string | null;
  last_status: string | null;
  created_by_operator_id: string | null;
  created_by_email: string | null;
  created_at: string;
  updated_at: string;
};

export type ScheduledTaskListData = {
  items: ScheduledTaskItem[];
  total: number;
  page: number;
  page_size: number;
};

export function formatScheduleDateTime(
  value: string | null | undefined,
  fallback = "Never",
): string {
  if (!value) return fallback;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return fallback;
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "short",
  }).format(parsed);
}

export function scheduledTaskFromUnknown(value: unknown): ScheduledTaskItem | null {
  if (typeof value !== "object" || value === null) return null;
  const record = value as Record<string, unknown>;
  if (
    typeof record.id !== "string" ||
    typeof record.name !== "string" ||
    typeof record.enabled !== "boolean" ||
    typeof record.target_type !== "string" ||
    typeof record.target_id !== "string" ||
    typeof record.cron_expression !== "string" ||
    typeof record.timezone !== "string" ||
    typeof record.kind !== "string" ||
    typeof record.next_run_at !== "string"
  ) {
    return null;
  }
  return {
    id: record.id,
    name: record.name,
    description: typeof record.description === "string" ? record.description : null,
    enabled: record.enabled,
    target_type: (record.target_type === "site" ? "site" : "agent") as ScheduledTaskTargetType,
    target_id: record.target_id,
    cron_expression: record.cron_expression,
    timezone: record.timezone,
    kind: record.kind,
    script_version_id: typeof record.script_version_id === "string" ? record.script_version_id : null,
    payload: typeof record.payload === "object" && record.payload !== null ? (record.payload as Record<string, unknown>) : {},
    concurrency_policy: (record.concurrency_policy === "queue" || record.concurrency_policy === "allow" ? record.concurrency_policy : "skip") as ScheduledConcurrencyPolicy,
    misfire_policy: (record.misfire_policy === "skip" ? "skip" : "run_once") as ScheduledMisfirePolicy,
    next_run_at: record.next_run_at,
    last_run_at: typeof record.last_run_at === "string" ? record.last_run_at : null,
    last_status: typeof record.last_status === "string" ? record.last_status : null,
    created_by_operator_id: typeof record.created_by_operator_id === "string" ? record.created_by_operator_id : null,
    created_by_email: typeof record.created_by_email === "string" ? record.created_by_email : null,
    created_at: typeof record.created_at === "string" ? record.created_at : record.next_run_at,
    updated_at: typeof record.updated_at === "string" ? record.updated_at : record.next_run_at,
  };
}

export function scheduledTaskListFromUnknown(value: unknown): ScheduledTaskListData | null {
  if (typeof value !== "object" || value === null) return null;
  const record = value as Record<string, unknown>;
  if (!Array.isArray(record.items) || typeof record.total !== "number") return null;

  const items: ScheduledTaskItem[] = [];
  for (const rawItem of record.items) {
    const item = scheduledTaskFromUnknown(rawItem);
    if (item) items.push(item);
  }

  return {
    items,
    total: record.total,
    page: typeof record.page === "number" ? record.page : 1,
    page_size: typeof record.page_size === "number" ? record.page_size : 50,
  };
}
