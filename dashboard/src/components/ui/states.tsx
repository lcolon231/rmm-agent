// SPDX-License-Identifier: AGPL-3.0-only

import { Inbox, RefreshCw, TriangleAlert, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

import { Button } from "./button";
import { cx } from "./cx";

type StateShellProps = {
  icon: LucideIcon;
  iconClass: string;
  title: string;
  body: string;
  action?: ReactNode;
  role?: "status" | "alert";
};

function StateShell({ icon: Icon, iconClass, title, body, action, role }: StateShellProps) {
  return (
    <div role={role} className="flex flex-col items-center gap-2 px-6 py-10 text-center">
      <span className={cx("flex size-12 items-center justify-center rounded-full", iconClass)}>
        <Icon size={22} aria-hidden="true" />
      </span>
      <h3 className="m-0 mt-1 text-base font-semibold text-(--ink)">{title}</h3>
      <p className="m-0 max-w-[420px] text-sm text-(--muted)">{body}</p>
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}

type EmptyStateProps = {
  title: string;
  body: string;
  icon?: LucideIcon;
  actionLabel?: string;
  onAction?: () => void;
};

/** "No results" uses actionLabel "Clear filters". */
export function EmptyState({ title, body, icon = Inbox, actionLabel, onAction }: EmptyStateProps) {
  return (
    <StateShell
      icon={icon}
      iconClass="bg-(--primary-tint) text-(--primary-strong)"
      title={title}
      body={body}
      role="status"
      action={actionLabel && onAction ? <Button onClick={onAction}>{actionLabel}</Button> : null}
    />
  );
}

type ErrorStateProps = {
  title?: string;
  /** What failed. "Nothing was changed." is always appended. */
  body: string;
  onRetry?: () => void;
};

export function ErrorState({ title = "This could not be loaded", body, onRetry }: ErrorStateProps) {
  const sentence = body.trim().replace(/\.?$/, ".");
  return (
    <StateShell
      icon={TriangleAlert}
      iconClass="bg-(--amber-soft) text-[#89500b]"
      title={title}
      body={`${sentence} Nothing was changed.`}
      role="alert"
      action={onRetry ? <Button icon={RefreshCw} onClick={onRetry}>Try again</Button> : null}
    />
  );
}

/** Placeholder bars for table or card content while it loads. */
export function Skeleton({ rows = 4, label = "Loading" }: { rows?: number; label?: string }) {
  return (
    <div aria-busy="true" aria-label={label} role="status" className="grid gap-3 px-5 py-4">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="flex items-center gap-4">
          <span className="block h-3.5 w-1/4 rounded bg-[#ece9f5]" />
          <span className="block h-3.5 flex-1 rounded bg-(--fog)" />
          <span className="block h-3.5 w-16 rounded bg-[#ece9f5]" />
        </div>
      ))}
    </div>
  );
}
