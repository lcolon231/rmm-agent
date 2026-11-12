// SPDX-License-Identifier: AGPL-3.0-only

// Plain-language status words for the Automation screens (script library,
// tasks, schedules). Loaded directly by node:test, so no "@/" imports.

import type { CommandStatus } from "./task-runs-core";

export type Tone = "ok" | "warn" | "crit" | "off" | "info";
export type Badge = { tone: Tone; label: string };

export type ScriptStateKey = "draft" | "approved" | "rejected" | "deprecated";

/** Script library state → fixed badge vocabulary. A draft is never shown as approved. */
export function scriptBadge(state: ScriptStateKey): Badge {
  switch (state) {
    case "approved":
      return { tone: "ok", label: "Approved" };
    case "rejected":
      return { tone: "crit", label: "Rejected" };
    case "deprecated":
      return { tone: "off", label: "Disabled" };
    default:
      return { tone: "warn", label: "Needs review" };
  }
}

const SCRIPT_RANK: Record<ScriptStateKey, number> = { draft: 0, rejected: 1, approved: 2, deprecated: 3 };

/** Waiting for review first, then rejected, approved, retired; stable otherwise. */
export function sortScriptsByAttention<T>(items: readonly T[], stateOf: (item: T) => ScriptStateKey): T[] {
  return items
    .map((item, index) => ({ item, index }))
    .sort((a, b) => SCRIPT_RANK[stateOf(a.item)] - SCRIPT_RANK[stateOf(b.item)] || a.index - b.index)
    .map(({ item }) => item);
}

const TASK_RANK: Record<CommandStatus, number> = {
  failed: 0,
  expired: 1,
  queued: 2,
  dispatched: 3,
  running: 3,
  result_pending: 3,
  succeeded: 4,
};

/** Failed first, then expired, waiting, running, completed; newest-first order kept within each. */
export function sortTaskRunsByAttention<T extends { status: CommandStatus }>(items: readonly T[]): T[] {
  return items
    .map((item, index) => ({ item, index }))
    .sort((a, b) => TASK_RANK[a.item.status] - TASK_RANK[b.item.status] || a.index - b.index)
    .map(({ item }) => item);
}

/**
 * What the scheduler recorded for the last run. "dispatched" only means the
 * commands were sent, never that they completed, so it is not shown as done.
 */
export function scheduleLastResult(lastStatus: string | null): { text: string; attention: boolean } {
  switch (lastStatus) {
    case null:
      return { text: "Has not run yet", attention: false };
    case "dispatched":
      return { text: "Sent to devices", attention: false };
    case "approval_required":
      return { text: "Not sent: needs approval", attention: true };
    case "skipped":
      return { text: "Not sent: skipped", attention: true };
    case "misfire_skipped":
      return { text: "Not sent: missed by more than a day", attention: true };
    case "power_operation_refused":
      return { text: "Not sent: restarts cannot be scheduled", attention: true };
    default:
      return { text: `Not confirmed (${lastStatus})`, attention: true };
  }
}
