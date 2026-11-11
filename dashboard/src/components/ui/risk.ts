// SPDX-License-Identifier: AGPL-3.0-only

import type { StatusTone } from "./status-badge";

/**
 * Default list order is always by risk: critical, offline, warning, healthy.
 * Waiting/in-progress items sit after warnings; they need watching, not action.
 */
const RISK_RANK: Record<StatusTone, number> = { crit: 0, off: 1, warn: 2, info: 3, ok: 4 };

export function riskRank(tone: StatusTone): number {
  return RISK_RANK[tone];
}

/** Stable sort, most urgent first. Does not mutate the input. */
export function sortByRisk<T>(rows: readonly T[], toneOf: (row: T) => StatusTone): T[] {
  return rows
    .map((row, index) => ({ row, index }))
    .sort((a, b) => riskRank(toneOf(a.row)) - riskRank(toneOf(b.row)) || a.index - b.index)
    .map(({ row }) => row);
}
