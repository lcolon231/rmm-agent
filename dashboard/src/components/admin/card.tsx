// SPDX-License-Identifier: AGPL-3.0-only

import type { ReactNode } from "react";

import { cx } from "../ui/cx";
import { cardClass } from "../ui/stat-tile";

/** Card with a titled header, used for forms and key/value blocks. */
export function Card({
  title,
  sub,
  action,
  children,
  className,
  bodyClassName = "grid gap-4 px-5 py-5",
}: {
  title: string;
  sub?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section aria-label={title} className={cx(cardClass, "overflow-hidden", className)}>
      <header className="flex flex-wrap items-start justify-between gap-3 border-b border-(--line) px-5 py-4">
        <div className="grid gap-0.5">
          <h2 className="m-0 text-base font-semibold text-(--ink)">{title}</h2>
          {sub ? <p className="m-0 text-xs text-(--muted)">{sub}</p> : null}
        </div>
        {action}
      </header>
      <div className={bodyClassName}>{children}</div>
    </section>
  );
}

/** Hostnames, IDs, fingerprints and other machine text. */
export function Mono({ children }: { children: ReactNode }) {
  return <span className="font-(family-name:--font-data) text-[13px] break-all">{children}</span>;
}
