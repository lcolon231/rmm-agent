// SPDX-License-Identifier: AGPL-3.0-only

import type { ReactNode } from "react";

import { cx } from "../ui/cx";
import { cardClass } from "../ui/stat-tile";

/** Detail-page block: a titled card with an optional muted second line. */
export function Card({ title, sub, children }: { title: string; sub?: ReactNode; children: ReactNode }) {
  return (
    <section aria-label={title} className={cx(cardClass, "overflow-hidden")}>
      <header className="grid gap-0.5 border-b border-(--line) px-5 py-4">
        <h2 className="m-0 text-base font-semibold text-(--ink)">{title}</h2>
        {sub ? <p className="m-0 text-xs text-(--muted)">{sub}</p> : null}
      </header>
      {children}
    </section>
  );
}
