// SPDX-License-Identifier: AGPL-3.0-only

/** Maintenance-window presentation and validation (issue #211).
 *
 * The management service remains the sole authority: it re-evaluates coverage
 * when a restart or shutdown is signed and fails closed without it. Everything
 * here exists so an operator can see the same answer *before* dispatching and
 * can create the window the server will require. Coverage is therefore mirrored
 * from `monitoring.active_maintenance_windows` and `_apply_power_operation_policy`:
 *
 *   - scope match (global, or client/site/agent equal to the endpoint's),
 *   - `starts_at <= now < ends_at`,
 *   - for recurring windows, an open weekly occurrence,
 *   - and, for power actions, `now + delay <= ends_at` of the earliest-ending
 *     matching window, because that is the window the server signs against.
 */

import { formatMonitoringScope, type MonitoringScope } from "./monitoring-core.ts";

export type MaintenanceRecurrence = {
  days: number[];
  start: string;
  duration_minutes: number;
};

export type MaintenanceWindow = {
  id: string;
  name: string;
  scope: MonitoringScope;
  scope_id: string | null;
  starts_at: string;
  ends_at: string;
  timezone: string;
  recurrence: MaintenanceRecurrence | null;
  created_by: string | null;
  created_at: string;
};

export type MaintenanceTarget = {
  agentId: string;
  siteId: string | null;
  clientId: string | null;
};

/** A dashboard guardrail, not a server limit: absolute windows longer than this
 * are almost always a mistyped end date rather than a planned outage. */
export const MAX_WINDOW_DURATION_SECONDS = 30 * 24 * 3600;
export const MAX_WINDOW_NAME_LENGTH = 200;

const SCOPES: MonitoringScope[] = ["global", "client", "site", "agent"];
const WALL_TIME = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function recurrenceFromUnknown(value: unknown): MaintenanceRecurrence | null | undefined {
  if (value === null || value === undefined) return null;
  if (!isRecord(value)) return undefined;
  const { days, start, duration_minutes: duration } = value;
  if (!Array.isArray(days) || days.length < 1 || days.length > 7) return undefined;
  if (!days.every((day) => typeof day === "number" && Number.isInteger(day) && day >= 0 && day <= 6)) {
    return undefined;
  }
  if (typeof start !== "string" || !/^([01]\d|2[0-3]):[0-5]\d$/.test(start)) return undefined;
  if (typeof duration !== "number" || !Number.isInteger(duration) || duration < 1) return undefined;
  return { days: [...days].sort((a, b) => a - b), start, duration_minutes: duration };
}

export function maintenanceWindowFromUnknown(value: unknown): MaintenanceWindow | null {
  if (!isRecord(value)) return null;
  const { id, name, scope, scope_id: scopeId, starts_at: starts, ends_at: ends } = value;
  if (typeof id !== "string" || !id) return null;
  if (typeof name !== "string" || !name) return null;
  if (typeof scope !== "string" || !SCOPES.includes(scope as MonitoringScope)) return null;
  if (scopeId !== null && scopeId !== undefined && typeof scopeId !== "string") return null;
  if (typeof starts !== "string" || Number.isNaN(Date.parse(starts))) return null;
  if (typeof ends !== "string" || Number.isNaN(Date.parse(ends))) return null;
  const recurrence = recurrenceFromUnknown(value.recurrence);
  if (recurrence === undefined) return null;
  const createdAt = value.created_at;
  if (typeof createdAt !== "string" || Number.isNaN(Date.parse(createdAt))) return null;
  return {
    id,
    name,
    scope: scope as MonitoringScope,
    scope_id: typeof scopeId === "string" ? scopeId : null,
    starts_at: starts,
    ends_at: ends,
    timezone: typeof value.timezone === "string" && value.timezone ? value.timezone : "UTC",
    recurrence,
    created_by: typeof value.created_by === "string" ? value.created_by : null,
    created_at: createdAt,
  };
}

export function maintenanceWindowListFromUnknown(value: unknown): MaintenanceWindow[] | null {
  if (!Array.isArray(value)) return null;
  const windows: MaintenanceWindow[] = [];
  for (const item of value) {
    const window = maintenanceWindowFromUnknown(item);
    if (!window) return null;
    windows.push(window);
  }
  return windows;
}

// --------------------------------------------------------------------------- //
// Time-zone arithmetic
// --------------------------------------------------------------------------- //

type WallClock = {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
};

export function isValidTimeZone(timeZone: string): boolean {
  if (!timeZone.trim()) return false;
  try {
    new Intl.DateTimeFormat("en-US", { timeZone });
    return true;
  } catch {
    return false;
  }
}

/** The wall-clock reading a zone shows for an absolute instant. */
export function zonedWallClock(atMs: number, timeZone: string): WallClock | null {
  if (!Number.isFinite(atMs)) return null;
  let parts: Intl.DateTimeFormatPart[];
  try {
    parts = new Intl.DateTimeFormat("en-US", {
      timeZone,
      hourCycle: "h23",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }).formatToParts(new Date(atMs));
  } catch {
    return null;
  }
  const read = (type: Intl.DateTimeFormatPartTypes) =>
    Number(parts.find((part) => part.type === type)?.value);
  const clock = {
    year: read("year"),
    month: read("month"),
    day: read("day"),
    hour: read("hour"),
    minute: read("minute"),
    second: read("second"),
  };
  return Object.values(clock).every((value) => Number.isInteger(value)) ? clock : null;
}

function wallClockAsPseudoUtc(clock: WallClock): number {
  return Date.UTC(clock.year, clock.month - 1, clock.day, clock.hour, clock.minute, clock.second);
}

function zoneOffsetMs(atMs: number, timeZone: string): number | null {
  const clock = zonedWallClock(atMs, timeZone);
  if (!clock) return null;
  // The offset is how far the zone's wall clock leads UTC at this instant.
  return wallClockAsPseudoUtc(clock) - Math.floor(atMs / 1000) * 1000;
}

/** Resolve a "YYYY-MM-DDTHH:MM" wall time in `timeZone` to an absolute instant.
 *
 * Two passes: the first uses the offset at the naive instant, the second uses
 * the offset actually in force at the candidate result, which is what makes the
 * answer correct on either side of a DST transition. Times inside a spring-
 * forward gap resolve to the instant the clock jumps to, which is the same
 * behaviour a calendar application shows.
 */
export function zonedWallTimeToUtc(wallTime: string, timeZone: string): number | null {
  const match = WALL_TIME.exec(wallTime.trim());
  if (!match || !isValidTimeZone(timeZone)) return null;
  const [, year, month, day, hour, minute, second] = match;
  const clock: WallClock = {
    year: Number(year),
    month: Number(month),
    day: Number(day),
    hour: Number(hour),
    minute: Number(minute),
    second: Number(second ?? "0"),
  };
  if (clock.month < 1 || clock.month > 12 || clock.day < 1 || clock.day > 31) return null;
  const naive = wallClockAsPseudoUtc(clock);
  const firstOffset = zoneOffsetMs(naive, timeZone);
  if (firstOffset === null) return null;
  const candidate = naive - firstOffset;
  const secondOffset = zoneOffsetMs(candidate, timeZone);
  if (secondOffset === null) return null;
  const resolved = naive - secondOffset;
  // Verify the round trip; a gap instant will not read back identically, and the
  // candidate (the post-jump instant) is the honest answer there.
  const readBack = zonedWallClock(resolved, timeZone);
  return readBack && wallClockAsPseudoUtc(readBack) === naive ? resolved : candidate;
}

/** Format an instant as the "YYYY-MM-DDTHH:MM" value a datetime-local input wants. */
export function formatWallTimeInput(atMs: number, timeZone: string): string {
  const clock = zonedWallClock(atMs, timeZone);
  if (!clock) return "";
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${String(clock.year).padStart(4, "0")}-${pad(clock.month)}-${pad(clock.day)}T${pad(clock.hour)}:${pad(clock.minute)}`;
}

// --------------------------------------------------------------------------- //
// Coverage
// --------------------------------------------------------------------------- //

export function windowMatchesTarget(window: MaintenanceWindow, target: MaintenanceTarget): boolean {
  switch (window.scope) {
    case "global":
      return true;
    case "client":
      return target.clientId !== null && window.scope_id === target.clientId;
    case "site":
      return target.siteId !== null && window.scope_id === target.siteId;
    case "agent":
      return window.scope_id === target.agentId;
  }
}

/** Whether a weekly occurrence is open, mirroring the server's day-and-previous-day scan.
 *
 * Wall-clock arithmetic in the window's zone; during the single ambiguous hour
 * of a DST transition this can disagree with the server by an hour, which is
 * why the server — not this — decides whether a dispatch is authorized.
 */
function recurrenceOpenAt(
  recurrence: MaintenanceRecurrence,
  timeZone: string,
  atMs: number,
): boolean {
  const local = zonedWallClock(atMs, isValidTimeZone(timeZone) ? timeZone : "UTC");
  if (!local) return false;
  const [hour, minute] = recurrence.start.split(":").map(Number);
  const localMs = wallClockAsPseudoUtc(local);
  const days = new Set(recurrence.days);
  for (const offset of [0, 1]) {
    const dayMs = localMs - offset * 86_400_000;
    const day = new Date(dayMs);
    // ISO weekday with Monday as 0, matching the server's day numbering.
    const weekday = (day.getUTCDay() + 6) % 7;
    if (!days.has(weekday)) continue;
    const occurrenceStart = Date.UTC(
      day.getUTCFullYear(),
      day.getUTCMonth(),
      day.getUTCDate(),
      hour,
      minute,
    );
    const elapsed = localMs - occurrenceStart;
    if (elapsed >= 0 && elapsed < recurrence.duration_minutes * 60_000) return true;
  }
  return false;
}

export function windowOpenAt(window: MaintenanceWindow, atMs: number): boolean {
  const starts = Date.parse(window.starts_at);
  const ends = Date.parse(window.ends_at);
  if (Number.isNaN(starts) || Number.isNaN(ends)) return false;
  if (atMs < starts || atMs >= ends) return false;
  return window.recurrence === null || recurrenceOpenAt(window.recurrence, window.timezone, atMs);
}

export type MaintenanceWindowState = "active" | "between_occurrences" | "upcoming" | "expired";

export function windowStateAt(window: MaintenanceWindow, atMs: number): MaintenanceWindowState {
  const starts = Date.parse(window.starts_at);
  const ends = Date.parse(window.ends_at);
  if (Number.isNaN(starts) || Number.isNaN(ends)) return "expired";
  if (atMs >= ends) return "expired";
  if (atMs < starts) return "upcoming";
  return windowOpenAt(window, atMs) ? "active" : "between_occurrences";
}

export function windowsForTarget(
  windows: MaintenanceWindow[],
  target: MaintenanceTarget,
): MaintenanceWindow[] {
  return windows.filter((window) => windowMatchesTarget(window, target));
}

export type PowerWindowCoverage =
  | { status: "no_window" }
  | {
      status: "covered" | "delay_exceeds_window";
      window: MaintenanceWindow;
      endsAtMs: number;
      secondsRemaining: number;
    };

/** The coverage decision the server will reach for a power action dispatched now.
 *
 * The earliest-ending matching window is chosen because that is the window the
 * server signs against, so a longer window running in parallel never disguises
 * a delay that outlives the one being relied upon.
 */
export function powerWindowCoverage(
  windows: MaintenanceWindow[],
  target: MaintenanceTarget,
  delaySeconds: number,
  atMs: number,
): PowerWindowCoverage {
  const open = windowsForTarget(windows, target).filter((window) => windowOpenAt(window, atMs));
  if (open.length === 0) return { status: "no_window" };
  const window = open.reduce((earliest, candidate) => {
    const a = Date.parse(candidate.ends_at);
    const b = Date.parse(earliest.ends_at);
    if (a !== b) return a < b ? candidate : earliest;
    return candidate.id < earliest.id ? candidate : earliest;
  });
  const endsAtMs = Date.parse(window.ends_at);
  const secondsRemaining = Math.max(0, Math.floor((endsAtMs - atMs) / 1000));
  return {
    status: atMs + delaySeconds * 1000 <= endsAtMs ? "covered" : "delay_exceeds_window",
    window,
    endsAtMs,
    secondsRemaining,
  };
}

// --------------------------------------------------------------------------- //
// Creation form
// --------------------------------------------------------------------------- //

export type MaintenanceWindowFormInput = {
  name: string;
  scope: MonitoringScope;
  scopeId: string;
  startsAt: string;
  endsAt: string;
  timeZone: string;
  /** When set, the window must already be open and stay open this long. */
  requiredCoverageSeconds?: number | null;
};

export type MaintenanceWindowCreateRequest = {
  name: string;
  scope: MonitoringScope;
  scope_id: string | null;
  starts_at: string;
  ends_at: string;
  timezone: string;
};

export type MaintenanceWindowFormResult =
  | { ok: true; request: MaintenanceWindowCreateRequest; startsAtMs: number; endsAtMs: number }
  | { ok: false; error: string };

/** Identity and scope rules, shared by the form and the API proxy. */
function validateNameAndScope(
  name: string,
  scope: unknown,
  scopeId: string,
): { ok: true; name: string; scope: MonitoringScope; scopeId: string | null } | { ok: false; error: string } {
  const trimmed = name.trim();
  if (trimmed.length < 1 || trimmed.length > MAX_WINDOW_NAME_LENGTH) {
    return { ok: false, error: `Enter a window name of up to ${MAX_WINDOW_NAME_LENGTH} characters.` };
  }
  if (typeof scope !== "string" || !SCOPES.includes(scope as MonitoringScope)) {
    return { ok: false, error: "Choose a global, client, site, or endpoint scope." };
  }
  const typedScope = scope as MonitoringScope;
  const target = scopeId.trim();
  if (typedScope === "global" && target) {
    return { ok: false, error: "A global window covers every endpoint and takes no target." };
  }
  if (typedScope !== "global" && (!target || target.length > 36)) {
    return {
      ok: false,
      error: `Choose the ${formatWindowScope(typedScope).toLowerCase()} this window covers.`,
    };
  }
  return { ok: true, name: trimmed, scope: typedScope, scopeId: typedScope === "global" ? null : target };
}

/** Span rules, shared by the form and the API proxy. */
function validateSpan(
  startsAtMs: number | null,
  endsAtMs: number | null,
  nowMs: number,
): { ok: true } | { ok: false; error: string } {
  if (startsAtMs === null || endsAtMs === null) {
    return { ok: false, error: "Enter a start and end date and time." };
  }
  if (endsAtMs <= startsAtMs) {
    return { ok: false, error: "The window must end after it starts." };
  }
  if (endsAtMs - startsAtMs > MAX_WINDOW_DURATION_SECONDS * 1000) {
    return {
      ok: false,
      error: `Maintenance windows created here are limited to ${MAX_WINDOW_DURATION_SECONDS / 86_400} days.`,
    };
  }
  if (endsAtMs <= nowMs) {
    return { ok: false, error: "The window must end in the future to suppress or authorize anything." };
  }
  return { ok: true };
}

export function validateMaintenanceWindowForm(
  input: MaintenanceWindowFormInput,
  nowMs: number,
): MaintenanceWindowFormResult {
  const identity = validateNameAndScope(input.name, input.scope, input.scopeId);
  if (!identity.ok) return identity;
  const timeZone = input.timeZone.trim() || "UTC";
  if (!isValidTimeZone(timeZone)) {
    return { ok: false, error: "Choose a valid IANA time zone such as UTC or America/New_York." };
  }
  const startsAtMs = zonedWallTimeToUtc(input.startsAt, timeZone);
  const endsAtMs = zonedWallTimeToUtc(input.endsAt, timeZone);
  const span = validateSpan(startsAtMs, endsAtMs, nowMs);
  if (!span.ok) return span;
  const startsAt = startsAtMs as number;
  const endsAt = endsAtMs as number;
  const required = input.requiredCoverageSeconds ?? null;
  if (required !== null) {
    if (startsAt > nowMs) {
      return {
        ok: false,
        error: "This window must already be open to authorize the prepared power action. Start it now.",
      };
    }
    if (endsAt < nowMs + required * 1000) {
      return {
        ok: false,
        error: `The window closes before the ${formatDurationSeconds(required)} delay elapses. Extend it past ${formatDurationSeconds(required)} from now.`,
      };
    }
  }
  return {
    ok: true,
    request: {
      name: identity.name,
      scope: identity.scope,
      scope_id: identity.scopeId,
      starts_at: new Date(startsAt).toISOString(),
      ends_at: new Date(endsAt).toISOString(),
      timezone: timeZone,
    },
    startsAtMs: startsAt,
    endsAtMs: endsAt,
  };
}

/** Re-validate the wire shape the browser posts to the dashboard's API proxy.
 *
 * The proxy never trusts the client's arithmetic: the same identity, scope, and
 * span rules run again here before anything reaches the management service. */
export function validateMaintenanceWindowRequest(
  body: unknown,
  nowMs: number,
): { ok: true; request: MaintenanceWindowCreateRequest } | { ok: false; error: string } {
  if (!isRecord(body)) return { ok: false, error: "The maintenance window request was malformed." };
  const allowed = ["name", "scope", "scope_id", "starts_at", "ends_at", "timezone"];
  if (Object.keys(body).some((key) => !allowed.includes(key))) {
    return { ok: false, error: "The maintenance window request carried unsupported fields." };
  }
  if (typeof body.name !== "string") {
    return { ok: false, error: `Enter a window name of up to ${MAX_WINDOW_NAME_LENGTH} characters.` };
  }
  const scopeId = body.scope_id;
  if (scopeId !== null && scopeId !== undefined && typeof scopeId !== "string") {
    return { ok: false, error: "Choose a global, client, site, or endpoint scope." };
  }
  const identity = validateNameAndScope(body.name, body.scope, typeof scopeId === "string" ? scopeId : "");
  if (!identity.ok) return identity;
  const timeZone = typeof body.timezone === "string" && body.timezone.trim()
    ? body.timezone.trim()
    : "UTC";
  if (!isValidTimeZone(timeZone)) {
    return { ok: false, error: "Choose a valid IANA time zone such as UTC or America/New_York." };
  }
  const parse = (value: unknown) => {
    if (typeof value !== "string") return null;
    const parsed = Date.parse(value);
    return Number.isNaN(parsed) ? null : parsed;
  };
  const startsAtMs = parse(body.starts_at);
  const endsAtMs = parse(body.ends_at);
  const span = validateSpan(startsAtMs, endsAtMs, nowMs);
  if (!span.ok) return span;
  return {
    ok: true,
    request: {
      name: identity.name,
      scope: identity.scope,
      scope_id: identity.scopeId,
      // Normalized to UTC instants so the service always receives an explicit offset.
      starts_at: new Date(startsAtMs as number).toISOString(),
      ends_at: new Date(endsAtMs as number).toISOString(),
      timezone: timeZone,
    },
  };
}

// --------------------------------------------------------------------------- //
// Navigation from a refused power action
// --------------------------------------------------------------------------- //

export const MAINTENANCE_WINDOW_ERROR_CODES = [
  "power_operation_maintenance_window_required",
  "power_operation_delay_exceeds_maintenance_window",
  "patch_install_maintenance_window_required",
] as const;

export type MaintenanceWindowErrorCode = (typeof MAINTENANCE_WINDOW_ERROR_CODES)[number];

export function isMaintenanceWindowErrorCode(
  code: unknown,
): code is MaintenanceWindowErrorCode {
  return typeof code === "string"
    && (MAINTENANCE_WINDOW_ERROR_CODES as readonly string[]).includes(code);
}

/** A same-origin dashboard path, or null. Guards the `return` query parameter
 * so a crafted link can never bounce an operator to another origin. */
export function safeReturnPath(value: unknown): string | null {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//")) return null;
  // No scheme-relative escape, no control characters, and no backslash, which
  // some clients normalize into a forward slash.
  if (value.length > 512 || /[\s\\]|[\u0000-\u001f\u007f]/.test(value)) return null;
  return value;
}

export type MaintenanceWindowPromptContext = {
  endpointId: string;
  hostname: string;
  delaySeconds?: number | null;
  returnPath?: string | null;
};

/** The link offered beside a refused power action. It prefills an endpoint-scoped
 * window that is long enough for the prepared delay and carries a return path,
 * and is opened in a new tab so the reviewed command survives the detour. */
export function maintenanceWindowPromptHref(context: MaintenanceWindowPromptContext): string {
  const query = new URLSearchParams({
    scope: "agent",
    scope_id: context.endpointId,
    name: `Power action — ${context.hostname}`.slice(0, MAX_WINDOW_NAME_LENGTH),
  });
  if (context.delaySeconds) query.set("cover_seconds", String(context.delaySeconds));
  const returnPath = safeReturnPath(context.returnPath);
  if (returnPath) query.set("return", returnPath);
  return `/maintenance-windows?${query.toString()}`;
}

// --------------------------------------------------------------------------- //
// Presentation
// --------------------------------------------------------------------------- //

export function formatDurationSeconds(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return "0 minutes";
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const parts = [
    days ? `${days} day${days === 1 ? "" : "s"}` : null,
    hours ? `${hours} hour${hours === 1 ? "" : "s"}` : null,
    minutes ? `${minutes} minute${minutes === 1 ? "" : "s"}` : null,
  ].filter(Boolean) as string[];
  if (parts.length === 0) return `${seconds} second${seconds === 1 ? "" : "s"}`;
  return parts.slice(0, 2).join(" ");
}

const WEEKDAY_LABELS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

export function describeRecurrence(recurrence: MaintenanceRecurrence | null): string {
  if (!recurrence) return "Absolute span";
  const days = recurrence.days.map((day) => WEEKDAY_LABELS[day] ?? day).join(", ");
  return `Weekly · ${days} at ${recurrence.start} for ${formatDurationSeconds(recurrence.duration_minutes * 60)}`;
}

/** Scope names as an operator reads them: the API's "agent" is an endpoint here,
 * matching the rest of the dashboard's vocabulary. */
export function formatWindowScope(scope: MonitoringScope): string {
  return scope === "agent" ? "Endpoint" : formatMonitoringScope(scope);
}

export function describeWindowState(state: MaintenanceWindowState): string {
  return {
    active: "Active",
    between_occurrences: "Between occurrences",
    upcoming: "Upcoming",
    expired: "Closed",
  }[state];
}

export function formatWindowTarget(
  window: MaintenanceWindow,
  names: Map<string, string>,
): string {
  if (window.scope === "global") return "All managed endpoints";
  if (!window.scope_id) return "Unknown target";
  return names.get(window.scope_id) ?? window.scope_id;
}
