// SPDX-License-Identifier: AGPL-3.0-only

import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

import { cx } from "./cx";
import { toneStyles, type StatusTone } from "./status-badge";

export const cardClass = "rounded-[10px] border border-(--line) bg-(--paper) shadow-[0_1px_2px_rgb(24_16_46/4%)]";

type StatTileProps = {
  icon: LucideIcon;
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  tone?: StatusTone;
};

export function StatTile({ icon: Icon, label, value, sub, tone = "info" }: StatTileProps) {
  const { surface, text } = toneStyles[tone];
  return (
    <div className={cx(cardClass, "flex gap-3 p-4")}>
      <span className={cx("flex size-10 shrink-0 items-center justify-center rounded-lg", surface, text)}>
        <Icon size={18} aria-hidden="true" />
      </span>
      <dl className="m-0 grid min-w-0 gap-0.5">
        <dt className="text-[13px] text-(--muted)">{label}</dt>
        <dd className="m-0 text-2xl leading-[1.3] font-semibold text-(--ink)">{value}</dd>
        {sub ? <dd className="m-0 text-xs text-(--muted)">{sub}</dd> : null}
      </dl>
    </div>
  );
}

/** 4 columns from 1100px, 2 from 560px, 1 below. */
export function StatRow({ children }: { children: ReactNode }) {
  return <div className="grid grid-cols-1 gap-4 min-[560px]:grid-cols-2 min-[1100px]:grid-cols-4">{children}</div>;
}
