// SPDX-License-Identifier: AGPL-3.0-only

import { ChevronRight } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { cx, focusRing } from "../ui/cx";

export type Crumb = { label: string; href?: string };

/** 12px trail; the last item is the current page and is not a link. */
export function Breadcrumb({ items }: { items: readonly Crumb[] }) {
  return (
    <nav aria-label="Breadcrumb">
      <ol className="m-0 flex list-none flex-wrap items-center gap-1 p-0 text-xs">
        {items.map((item, index) => {
          const last = index === items.length - 1;
          return (
            <li key={`${item.label}-${index}`} className="flex items-center gap-1">
              {last || !item.href ? (
                <span aria-current={last ? "page" : undefined} className={last ? "text-(--muted)" : "text-(--slate)"}>
                  {item.label}
                </span>
              ) : (
                <Link href={item.href} className={cx("rounded text-(--primary-strong) no-underline hover:underline", focusRing)}>
                  {item.label}
                </Link>
              )}
              {last ? null : <ChevronRight size={12} aria-hidden="true" className="text-(--muted)" />}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

type PageHeaderProps = {
  breadcrumb: readonly Crumb[];
  title: ReactNode;
  /** Status badge beside the title on detail pages. */
  status?: ReactNode;
  /** One line, max 720px. */
  description?: ReactNode;
  /** One primary, at most one secondary. */
  actions?: ReactNode;
};

/** Breadcrumb and title row: the first two steps of every page. */
export function PageHeader({ breadcrumb, title, status, description, actions }: PageHeaderProps) {
  return (
    <header className="grid gap-3">
      <Breadcrumb items={breadcrumb} />
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="grid min-w-0 gap-1.5">
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="m-0 text-2xl leading-[1.3] font-semibold text-(--ink)">{title}</h1>
            {status}
          </div>
          {description ? <p className="m-0 max-w-[720px] text-sm leading-normal text-(--muted)">{description}</p> : null}
        </div>
        {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
    </header>
  );
}

/** Vertical rhythm for a page body: header, stats, tabs, table, 24px apart. */
export function PageStack({ children }: { children: ReactNode }) {
  return <div className="grid gap-6">{children}</div>;
}
