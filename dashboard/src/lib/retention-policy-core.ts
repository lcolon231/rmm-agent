// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Tenant retention policy presentation and editing rules (issue #311).
 *
 * Mirrors the #88 contract in `docs/RETENTION.md`. The bounds checks here are
 * hints that save a round trip; the server re-validates every value and stays
 * the authority on what is accepted and what is pruned.
 */

export const RETENTION_CATEGORY_NAMES = [
  "telemetry_days",
  "command_output_days",
  "command_record_days",
  "inventory_history_per_section",
  "alert_days",
  "notification_days",
  "evidence_default_days",
] as const;

export type RetentionCategoryName = (typeof RETENTION_CATEGORY_NAMES)[number];
export type RetentionUnit = "days" | "count";
export type RetentionSource = "default" | "tenant" | "floor" | "ceiling";

export const RETENTION_CATEGORY_LABELS: Record<
  RetentionCategoryName,
  { label: string; description: string }
> = {
  telemetry_days: { label: "Telemetry", description: "Heartbeats from this client's agents." },
  command_output_days: {
    label: "Command output",
    description: "Stdout and stderr text, cleared after the command completes.",
  },
  command_record_days: {
    label: "Command records",
    description: "Finished command rows, including scheduled task run history.",
  },
  inventory_history_per_section: {
    label: "Inventory history",
    description: "Snapshots kept per agent and section. The newest is never deleted.",
  },
  alert_days: {
    label: "Resolved alerts",
    description: "Resolved alerts with their events, observations and deliveries.",
  },
  notification_days: {
    label: "Notification deliveries",
    description: "Finished email and webhook deliveries and their attempts.",
  },
  evidence_default_days: {
    label: "Evidence default",
    description: "Default retention for new evidence vault records.",
  },
};

export const RETENTION_SOURCE_LABELS: Record<RetentionSource, string> = {
  default: "Platform default",
  tenant: "Client override",
  floor: "Raised to platform minimum",
  ceiling: "Lowered to platform maximum",
};

export type RetentionCategory = {
  name: RetentionCategoryName;
  unit: RetentionUnit;
  effective: number;
  source: RetentionSource;
  override: number | null;
  platformDefault: number;
  minimum: number;
  /** 0 means no ceiling. */
  maximum: number;
  foreverAllowed: boolean;
};

export type RetentionPolicy = {
  clientId: string;
  version: number;
  canEdit: boolean;
  setBy: string | null;
  updatedAt: string | null;
  pruningSuspended: boolean;
  categories: RetentionCategory[];
};

const SOURCES: readonly string[] = ["default", "tenant", "floor", "ceiling"];

function isCount(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

function categoryFromUnknown(
  name: RetentionCategoryName,
  value: unknown,
): RetentionCategory | null {
  if (!value || typeof value !== "object") return null;
  const raw = value as Record<string, unknown>;
  if (raw.unit !== "days" && raw.unit !== "count") return null;
  if (typeof raw.source !== "string" || !SOURCES.includes(raw.source)) return null;
  if (!isCount(raw.effective) || !isCount(raw.platform_default)
    || !isCount(raw.minimum) || !isCount(raw.maximum)) return null;
  if (raw.override !== null && !isCount(raw.override)) return null;
  return {
    name,
    unit: raw.unit,
    effective: raw.effective,
    source: raw.source as RetentionSource,
    override: raw.override as number | null,
    platformDefault: raw.platform_default,
    minimum: raw.minimum,
    maximum: raw.maximum,
    foreverAllowed: raw.forever_allowed === true,
  };
}

/** Parse the server's effective-policy view, or `null` if it is malformed. */
export function retentionPolicyFromUnknown(value: unknown): RetentionPolicy | null {
  if (!value || typeof value !== "object") return null;
  const raw = value as Record<string, unknown>;
  if (typeof raw.client_id !== "string" || !isCount(raw.version)) return null;
  if (!raw.categories || typeof raw.categories !== "object") return null;
  const source = raw.categories as Record<string, unknown>;
  const categories: RetentionCategory[] = [];
  for (const name of RETENTION_CATEGORY_NAMES) {
    const parsed = categoryFromUnknown(name, source[name]);
    if (!parsed) return null;
    categories.push(parsed);
  }
  return {
    clientId: raw.client_id,
    version: raw.version,
    canEdit: raw.can_edit === true,
    setBy: typeof raw.set_by === "string" ? raw.set_by : null,
    updatedAt: typeof raw.updated_at === "string" ? raw.updated_at : null,
    pruningSuspended: raw.pruning_suspended === true,
    categories,
  };
}

export function formatRetention(value: number, unit: RetentionUnit): string {
  if (value === 0) return "Keep forever";
  if (unit === "count") return `${value} ${value === 1 ? "snapshot" : "snapshots"}`;
  return `${value} ${value === 1 ? "day" : "days"}`;
}

export type DraftMode = "inherit" | "forever" | "custom";
export type DraftValue = { mode: DraftMode; value: string };
export type RetentionDraft = Record<RetentionCategoryName, DraftValue>;

export function draftFromPolicy(policy: RetentionPolicy): RetentionDraft {
  const draft = {} as RetentionDraft;
  for (const entry of policy.categories) {
    draft[entry.name] = entry.override === null
      ? { mode: "inherit", value: "" }
      : entry.override === 0
        ? { mode: "forever", value: "" }
        : { mode: "custom", value: String(entry.override) };
  }
  return draft;
}

export type RetentionValues = Record<RetentionCategoryName, number | null>;
export type DraftValidation =
  | { ok: true; values: RetentionValues }
  | { ok: false; errors: Partial<Record<RetentionCategoryName, string>> };

function boundsError(entry: RetentionCategory, value: number): string | null {
  if (value < entry.minimum) {
    return `Must be at least ${formatRetention(entry.minimum, entry.unit)}.`;
  }
  if (entry.maximum !== 0 && value > entry.maximum) {
    return `Must be at most ${formatRetention(entry.maximum, entry.unit)}.`;
  }
  return null;
}

/** Resolve a draft to API values, or per-field errors mirroring the server's bounds. */
export function validateDraft(policy: RetentionPolicy, draft: RetentionDraft): DraftValidation {
  const values = {} as RetentionValues;
  const errors: Partial<Record<RetentionCategoryName, string>> = {};
  for (const entry of policy.categories) {
    const field = draft[entry.name];
    if (field.mode === "inherit") {
      values[entry.name] = null;
    } else if (field.mode === "forever") {
      if (entry.foreverAllowed) values[entry.name] = 0;
      else errors[entry.name] = "This category cannot be kept forever.";
    } else if (!/^[1-9]\d*$/.test(field.value.trim())) {
      errors[entry.name] = "Enter a whole number above zero.";
    } else {
      const value = Number(field.value.trim());
      const error = boundsError(entry, value);
      if (error) errors[entry.name] = error;
      else values[entry.name] = value;
    }
  }
  return Object.keys(errors).length ? { ok: false, errors } : { ok: true, values };
}

/**
 * Whether `next` keeps data for less time (or fewer snapshots) than `current`.
 * Both are effective values, where 0 means keep forever.
 */
function retainsLess(current: number, next: number): boolean {
  if (next === 0) return false; // forever is never shorter than anything
  return current === 0 || next < current;
}

/**
 * Categories whose effective retention a save would shorten, in display order.
 * A null value inherits, so it is compared as the platform default it resolves to.
 */
export function shortenedCategories(
  policy: RetentionPolicy,
  values: RetentionValues,
): RetentionCategoryName[] {
  return policy.categories
    .filter((entry) => retainsLess(entry.effective, values[entry.name] ?? entry.platformDefault))
    .map((entry) => entry.name);
}

const ERROR_MESSAGES: Record<string, string> = {
  retention_below_minimum: "This value is below the platform minimum.",
  retention_above_maximum: "This value is above the platform maximum.",
  retention_value_invalid: "This value is not allowed for this category.",
  retention_policy_conflict:
    "Another administrator changed this policy. Review their changes before saving again.",
  retention_policy_not_found: "This client already uses the platform defaults.",
  client_not_found: "This client is no longer available to you.",
  step_up_required: "Confirm your security key to change retention.",
};

/** Operator-facing text for a server `detail.code`, or `null` when unknown. */
export function retentionErrorMessage(code: string | null | undefined): string | null {
  return code ? ERROR_MESSAGES[code] ?? null : null;
}

export type RetentionChange = {
  name: RetentionCategoryName;
  before: number | null;
  after: number | null;
  unit: RetentionUnit;
};

/** Saved overrides that differ between the policy the editor loaded and the current one. */
export function conflictChanges(
  loaded: RetentionPolicy,
  current: RetentionPolicy,
): RetentionChange[] {
  return current.categories.flatMap((entry) => {
    const before = loaded.categories.find((item) => item.name === entry.name)?.override ?? null;
    return before === entry.override
      ? []
      : [{ name: entry.name, before, after: entry.override, unit: entry.unit }];
  });
}
