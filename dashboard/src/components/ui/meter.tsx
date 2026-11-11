// SPDX-License-Identifier: AGPL-3.0-only

import { cx } from "./cx";

/** Same thresholds as the existing endpoint Meter. */
export const METER_WARN = 68;
export const METER_CRIT = 90;

export type MeterLevel = "normal" | "warn" | "crit";

export function meterLevel(value: number): MeterLevel {
  if (value >= METER_CRIT) return "crit";
  if (value >= METER_WARN) return "warn";
  return "normal";
}

const fill: Record<MeterLevel, string> = { normal: "bg-(--chrome-muted)", warn: "bg-(--amber)", crit: "bg-(--red)" };
const text: Record<MeterLevel, string> = { normal: "text-(--slate)", warn: "font-semibold text-[#89500b]", crit: "font-semibold text-(--red)" };

type MeterProps = {
  value: number | null;
  /** Accessible name, e.g. "Processor". */
  label: string;
};

export function Meter({ value, label }: MeterProps) {
  if (value === null) {
    return (
      <span className="text-(--muted)" aria-label={`${label}: no reading`}>
        —
      </span>
    );
  }
  const clamped = Math.min(100, Math.max(0, Math.round(value)));
  const level = meterLevel(clamped);
  return (
    <div className="flex items-center gap-2">
      <span className={cx("w-[34px] text-xs tabular-nums", text[level])}>{clamped}%</span>
      <span
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={clamped}
        data-level={level}
        className="block h-1.5 w-16 overflow-hidden rounded-full bg-[#ece9f5]"
      >
        <span className={cx("block h-full rounded-full", fill[level])} style={{ width: `${clamped}%` }} />
      </span>
    </div>
  );
}
