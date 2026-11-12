// SPDX-License-Identifier: AGPL-3.0-only

import Link from "next/link";

import { cx, focusRing } from "./cx";

export type TabLink = { label: string; href: string; current: boolean };

/**
 * Tabs that are separate routes. They are links, not an ARIA tablist,
 * because each one is a page you can share and go back to.
 */
export function TabNav({ label, tabs }: { label: string; tabs: readonly TabLink[] }) {
  return (
    <nav aria-label={label} className="flex overflow-x-auto border-b border-(--line)">
      {tabs.map((tab) => (
        <Link
          key={tab.href}
          href={tab.href}
          aria-current={tab.current ? "page" : undefined}
          className={cx(
            "-mb-px flex h-11 shrink-0 items-center border-b-2 px-4 font-semibold whitespace-nowrap no-underline",
            tab.current ? "border-(--primary-strong) text-(--primary-press)" : "border-transparent text-(--muted) hover:text-(--slate)",
            focusRing,
          )}
        >
          {tab.label}
        </Link>
      ))}
    </nav>
  );
}
