// SPDX-License-Identifier: AGPL-3.0-only

import { Search } from "lucide-react";
import Link from "next/link";
import type { ComponentPropsWithRef, ReactNode } from "react";

import { cx, focusRing } from "./cx";

/** Filter bar row: search, chips, spacer, then optional site select / export. */
export function FilterBar({ children, trailing }: { children: ReactNode; trailing?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-3 border-b border-(--line) px-5 py-4">
      {children}
      {trailing ? <div className="ml-auto flex flex-wrap items-center gap-3">{trailing}</div> : null}
    </div>
  );
}

type SearchFieldProps = Omit<ComponentPropsWithRef<"input">, "type"> & { label: string };

/** Visually label-less search box; `label` is its accessible name. */
export function SearchField({ label, className, ...rest }: SearchFieldProps) {
  return (
    <div className={cx("relative w-full max-w-[320px] min-w-[200px] flex-1", className)}>
      <Search size={16} aria-hidden="true" className="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-(--muted)" />
      <input
        type="search"
        aria-label={label}
        className={cx("h-10 w-full rounded-lg border border-(--line-strong) bg-(--paper) pr-3 pl-9 text-sm text-(--ink)", focusRing)}
        {...rest}
      />
    </div>
  );
}

const chipBase = "inline-flex h-9 items-center gap-1.5 rounded-full border px-3.5 text-[13px] font-semibold whitespace-nowrap no-underline";
const chipOn = "border-(--primary-on-dark) bg-(--primary-soft) text-(--primary-press)";
const chipOff = "border-(--line-strong) bg-(--paper) text-(--slate) hover:bg-(--primary-tint)";

type FilterChipProps = {
  selected: boolean;
  count?: number;
  children: string;
} & ({ href: string; onClick?: never } | { href?: never; onClick: () => void });

/**
 * A status filter. Pass `href` when the filter lives in URL parameters (the
 * default for list screens) or `onClick` for purely local filtering.
 */
export function FilterChip({ selected, count, children, href, onClick }: FilterChipProps) {
  const className = cx(chipBase, selected ? chipOn : chipOff, focusRing);
  const content = (
    <>
      {children}
      {count !== undefined ? <span className="tabular-nums opacity-80">{count}</span> : null}
    </>
  );
  if (href !== undefined) {
    return (
      <Link href={href} aria-current={selected ? "true" : undefined} className={className}>
        {content}
      </Link>
    );
  }
  return (
    <button type="button" aria-pressed={selected} onClick={onClick} className={className}>
      {content}
    </button>
  );
}
