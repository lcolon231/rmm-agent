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

export function scheduleErrorMessage(action: ScheduleAction, status: number): { message: string; status: number } {
  if (status === 401) return { message: "Your session expired. Sign in again.", status: 401 };
  if (status === 403) return { message: "Your role cannot manage scheduled tasks.", status: 403 };
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

async function authorize(request: Request, getSession: GetSession) {
  if (!isSameOriginRequest(request)) return json({ error: "Scheduled task request was rejected." }, 403);
  return authorizeSession(getSession, {
    minRole: "operator",
    signedOut: "Your session expired. Sign in again.",
    forbidden: "Your role cannot manage scheduled tasks.",
  });
}

function mappedError(action: ScheduleAction, error: unknown): Response {
  const upstream = upstreamError(error);
  const { message, status } = scheduleErrorMessage(action, upstream?.status ?? 503);
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
