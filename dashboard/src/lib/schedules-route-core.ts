// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Route cores for scheduled-task mutations (issue #280).
 *
 * These were the weakest handlers in the BFF: no origin check, the schedule id
 * spliced into the upstream path unencoded, and the upstream error message
 * echoed to the browser. Now every mutation is same-origin, operator-gated
 * (the service's floor), forwards only the create fields the service accepts,
 * and answers with fixed text plus an allowlisted record.
 */

import {
  authorizeSession,
  isRecord,
  isSameOriginRequest,
  json,
  readJsonBody,
  upstreamError,
  type GetSession,
} from "./bff-route-core.ts";
import { scheduledTaskFromUnknown } from "./scheduled-tasks-core.ts";
import { scriptVersionFromUnknown } from "./script-library-core.ts";

type ScheduleAction = "create" | "toggle" | "run-now";

const CREATE_FIELDS = [
  "name",
  "description",
  "enabled",
  "target_type",
  "target_id",
  "cron_expression",
  "timezone",
  "kind",
  "script_version_id",
  "payload",
  "concurrency_policy",
  "misfire_policy",
] as const;

const SIGNED_OUT = "Your session expired. Sign in again.";
const FORBIDDEN = "Your role cannot manage scheduled tasks.";

const failure: Record<ScheduleAction, string> = {
  create: "The scheduled task could not be created. Try again.",
  toggle: "The scheduled task could not be toggled. Try again.",
  "run-now": "The scheduled task could not be run. Try again.",
};

/** Upstream path for a per-task action; the id is always encoded. */
export function scheduledTaskActionPath(scheduleId: string, action: "toggle" | "run-now"): string {
  return `/api/v1/scheduled-tasks/${encodeURIComponent(scheduleId)}/${action}`;
}

export function scheduleCreateInputFromUnknown(value: unknown): Record<string, unknown> | null {
  if (!isRecord(value)) return null;
  const input: Record<string, unknown> = {};
  for (const field of CREATE_FIELDS) {
    if (field in value) input[field] = value[field];
  }
  return input;
}

export function scheduleErrorMessage(
  action: ScheduleAction,
  status: number,
  code: string | null = null,
): { message: string; status: number } {
  if (status === 409 && code === "script_version_not_approved") {
    return {
      message: "The chosen library script version is no longer approved, or its script was retired. Pick another script.",
      status: 409,
    };
  }
  if (status === 401) return { message: SIGNED_OUT, status: 401 };
  if (status === 403) return { message: FORBIDDEN, status: 403 };
  if (status === 404) {
    return {
      message: action === "create"
        ? "The selected target no longer exists."
        : "This scheduled task no longer exists.",
      status: 404,
    };
  }
  if (status === 400 || status === 422) {
    return { message: "Check the schedule name, target, cron expression, time zone, and command.", status: 400 };
  }
  if (status === 409) return { message: "That change conflicts with the schedule's current state.", status: 409 };
  return { message: failure[action], status: 502 };
}

/** Same operator floor for every schedule handler, reads included. */
function requireOperator(getSession: GetSession) {
  return authorizeSession(getSession, { minRole: "operator", signedOut: SIGNED_OUT, forbidden: FORBIDDEN });
}

async function authorize(request: Request, getSession: GetSession) {
  if (!isSameOriginRequest(request)) return json({ error: "Scheduled task request was rejected." }, 403);
  return requireOperator(getSession);
}

function mappedError(action: ScheduleAction, error: unknown): Response {
  const upstream = upstreamError(error);
  const { message, status } = scheduleErrorMessage(action, upstream?.status ?? 503, upstream?.code ?? null);
  return json({ error: message }, status);
}

function taskResponse(value: unknown, status = 200): Response {
  const task = scheduledTaskFromUnknown(value);
  return task
    ? json(task, status)
    : json({ error: "The management service returned an invalid scheduled task." }, 502);
}

export async function handleCreateSchedule(
  request: Request,
  deps: {
    getSession: GetSession;
    createScheduledTask: (sessionToken: string, input: Record<string, unknown>) => Promise<unknown>;
  },
): Promise<Response> {
  const auth = await authorize(request, deps.getSession);
  if (auth instanceof Response) return auth;
  const input = scheduleCreateInputFromUnknown(await readJsonBody(request));
  if (!input) return json({ error: "Invalid JSON request body." }, 400);
  try {
    return taskResponse(await deps.createScheduledTask(auth.sessionToken, input), 201);
  } catch (error) {
    return mappedError("create", error);
  }
}

export async function handleToggleSchedule(
  request: Request,
  scheduleId: string,
  deps: {
    getSession: GetSession;
    toggleScheduledTask: (sessionToken: string, scheduleId: string) => Promise<unknown>;
  },
): Promise<Response> {
  const auth = await authorize(request, deps.getSession);
  if (auth instanceof Response) return auth;
  try {
    return taskResponse(await deps.toggleScheduledTask(auth.sessionToken, scheduleId));
  } catch (error) {
    return mappedError("toggle", error);
  }
}

export async function handleRunScheduleNow(
  request: Request,
  scheduleId: string,
  deps: {
    getSession: GetSession;
    runScheduledTaskNow: (sessionToken: string, scheduleId: string) => Promise<unknown>;
  },
): Promise<Response> {
  const auth = await authorize(request, deps.getSession);
  if (auth instanceof Response) return auth;
  try {
    const result = await deps.runScheduledTaskNow(auth.sessionToken, scheduleId);
    if (!isRecord(result) || !Number.isSafeInteger(result.dispatched) || Number(result.dispatched) < 0) {
      return json({ error: "The management service returned an invalid run result." }, 502);
    }
    return json({ status: "triggered", dispatched: Number(result.dispatched) });
  } catch (error) {
    return mappedError("run-now", error);
  }
}

/**
 * The body of one library script version, for the New schedule drawer's
 * preview and payload (issue #358). The list API omits bodies, so the drawer
 * reads only the version the operator picked. Operator floor, like create.
 */
export async function handleScheduleScriptSource(
  _request: Request,
  scriptId: string,
  version: string,
  deps: {
    getSession: GetSession;
    getScriptVersion: (sessionToken: string, scriptId: string, version: number) => Promise<unknown>;
  },
): Promise<Response> {
  const auth = await requireOperator(deps.getSession);
  if (auth instanceof Response) return auth;
  const versionNumber = /^[1-9][0-9]{0,8}$/.test(version) ? Number(version) : null;
  if (versionNumber === null) return json({ error: "Unknown script version." }, 400);
  const unavailable = json({ error: "The script could not be loaded. Nothing was changed." }, 502);
  try {
    const loaded = scriptVersionFromUnknown(await deps.getScriptVersion(auth.sessionToken, scriptId, versionNumber));
    return loaded && typeof loaded.content === "string" ? json(loaded) : unavailable;
  } catch (error) {
    const status = upstreamError(error)?.status;
    if (status === 401) return json({ error: SIGNED_OUT }, 401);
    if (status === 404) return json({ error: "This script version no longer exists." }, 404);
    return unavailable;
  }
}
