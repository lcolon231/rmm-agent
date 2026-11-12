// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { useId, useRef, type KeyboardEvent, type ReactNode } from "react";

import { cx, focusRing } from "./cx";

export type TabItem = { id: string; label: string };

type TabsProps = {
  tabs: readonly TabItem[];
  value: string;
  onChange: (id: string) => void;
  label: string;
  children: ReactNode;
};

/**
 * Accessible tablist: arrow keys, Home and End move between tabs; only the
 * selected tab is in the Tab order. `children` is the active panel.
 */
export function Tabs({ tabs, value, onChange, label, children }: TabsProps) {
  const baseId = useId();
  const refs = useRef<Array<HTMLButtonElement | null>>([]);
  const activeIndex = Math.max(0, tabs.findIndex((tab) => tab.id === value));

  function move(event: KeyboardEvent<HTMLDivElement>) {
    const last = tabs.length - 1;
    const next =
      event.key === "ArrowRight" ? (activeIndex === last ? 0 : activeIndex + 1)
      : event.key === "ArrowLeft" ? (activeIndex === 0 ? last : activeIndex - 1)
      : event.key === "Home" ? 0
      : event.key === "End" ? last
      : null;
    if (next === null) return;
    event.preventDefault();
    onChange(tabs[next].id);
    refs.current[next]?.focus();
  }

  const active = tabs[activeIndex];
  return (
    <div className="grid gap-6">
      <div role="tablist" aria-label={label} onKeyDown={move} className="flex overflow-x-auto border-b border-(--line)">
        {tabs.map((tab, index) => {
          const selected = index === activeIndex;
          return (
            <button
              key={tab.id}
              ref={(node) => {
                refs.current[index] = node;
              }}
              id={`${baseId}-tab-${tab.id}`}
              type="button"
              role="tab"
              aria-selected={selected}
              aria-controls={`${baseId}-panel`}
              tabIndex={selected ? 0 : -1}
              onClick={() => onChange(tab.id)}
              className={cx(
                "-mb-px h-11 shrink-0 border-b-2 bg-transparent px-4 font-semibold whitespace-nowrap",
                selected ? "border-(--primary-strong) text-(--primary-press)" : "border-transparent text-(--muted) hover:text-(--slate)",
                focusRing,
              )}
            >
              {tab.label}
            </button>
          );
        })}
      </div>
      <div role="tabpanel" id={`${baseId}-panel`} aria-labelledby={active ? `${baseId}-tab-${active.id}` : undefined} tabIndex={0} className="outline-none">
        {children}
      </div>
    </div>
  );
}
