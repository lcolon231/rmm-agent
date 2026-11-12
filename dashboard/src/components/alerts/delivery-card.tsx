// SPDX-License-Identifier: AGPL-3.0-only

import type { LucideIcon } from "lucide-react";
import { Children, type ReactNode } from "react";

import type { ToneWord } from "@/lib/monitoring-view-core";

import { cx } from "../ui/cx";
import { cardClass } from "../ui/stat-tile";
import { EmptyState } from "../ui/states";
import { StatusBadge } from "../ui/status-badge";

/** Card shell shared by the email and webhook notification lists. */
export function DeliveryCard({
  title,
  sub,
  icon,
  emptyTitle,
  emptyBody,
  error,
  children,
}: {
  title: string;
  sub: string;
  icon: LucideIcon;
  emptyTitle: string;
  emptyBody: string;
  error?: string;
  children: ReactNode;
}) {
  const empty = Children.count(children) === 0;
  return (
    <section aria-label={title} className={cx(cardClass, "overflow-hidden")}>
      <header className="grid gap-0.5 border-b border-(--line) px-5 py-4">
        <h2 className="m-0 text-base font-semibold text-(--ink)">{title}</h2>
        <p className="m-0 text-xs text-(--muted)">{sub}</p>
      </header>
      {empty ? <EmptyState icon={icon} title={emptyTitle} body={emptyBody} /> : <ul className="m-0 list-none p-0">{children}</ul>}
      {error ? (
        <p role="alert" className="m-0 border-t border-(--line) px-5 py-3 text-sm text-(--red)">
          {error}
        </p>
      ) : null}
    </section>
  );
}

export function DeliveryRow({
  word,
  title,
  detail,
  time,
  attempts,
  action,
}: {
  word: ToneWord;
  title: ReactNode;
  detail: Array<string | null>;
  time: string;
  attempts: Array<{ id: string; text: string; time: string }>;
  action?: ReactNode;
}) {
  return (
    <li className="grid gap-2 border-t border-(--line) px-5 py-4 first:border-t-0">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="grid min-w-0 gap-1">
          <span className="flex flex-wrap items-center gap-2">
            <span className="font-semibold break-all text-(--ink)">{title}</span>
            <StatusBadge tone={word.tone}>{word.label}</StatusBadge>
          </span>
          {detail.filter(Boolean).map((line) => (
            <span key={line} className="text-[13px] text-(--muted)">
              {line}
            </span>
          ))}
        </div>
        <div className="flex flex-col items-end gap-2">
          <time className="text-xs whitespace-nowrap text-(--muted)">{time}</time>
          {action}
        </div>
      </div>
      {attempts.length ? (
        <details className="text-[13px] text-(--slate)">
          <summary className="cursor-pointer font-semibold text-(--primary-strong)">Attempt history</summary>
          <ol className="m-0 mt-2 grid gap-1 pl-5">
            {attempts.map((attempt) => (
              <li key={attempt.id} className="flex flex-wrap justify-between gap-3">
                <span>{attempt.text}</span>
                <time className="text-xs text-(--muted)">{attempt.time}</time>
              </li>
            ))}
          </ol>
        </details>
      ) : null}
    </li>
  );
}
