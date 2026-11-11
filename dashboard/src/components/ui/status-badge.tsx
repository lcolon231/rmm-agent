// SPDX-License-Identifier: AGPL-3.0-only

import { CircleAlert, CircleCheck, Clock, TriangleAlert, WifiOff, type LucideIcon } from "lucide-react";

import { cx } from "./cx";

/**
 * Fixed status vocabulary. Violet (`info`) means "in progress / waiting",
 * never health. Status is always colour + icon + word, never colour alone.
 */
export type StatusTone = "ok" | "warn" | "crit" | "off" | "info";

export const toneStyles: Record<StatusTone, { surface: string; text: string; icon: LucideIcon }> = {
  ok: { surface: "bg-(--success-soft)", text: "text-(--success)", icon: CircleCheck },
  warn: { surface: "bg-(--amber-soft)", text: "text-[#89500b]", icon: TriangleAlert },
  crit: { surface: "bg-(--red-soft)", text: "text-(--red)", icon: CircleAlert },
  off: { surface: "bg-(--fog)", text: "text-(--muted)", icon: WifiOff },
  info: { surface: "bg-(--primary-tint)", text: "text-(--primary-press)", icon: Clock },
};

type StatusBadgeProps = {
  tone: StatusTone;
  children: string;
  className?: string;
};

export function StatusBadge({ tone, children, className }: StatusBadgeProps) {
  const { surface, text, icon: Icon } = toneStyles[tone];
  return (
    <span
      data-tone={tone}
      className={cx(
        "inline-flex items-center gap-1.5 rounded-full py-[3px] pr-2.5 pl-2 text-xs leading-[18px] font-semibold whitespace-nowrap",
        surface,
        text,
        className,
      )}
    >
      <Icon size={14} aria-hidden="true" />
      {children}
    </span>
  );
}
