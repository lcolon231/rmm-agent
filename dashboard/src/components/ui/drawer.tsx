// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { X } from "lucide-react";
import { useId, type ReactNode } from "react";

import { cx, focusRing } from "./cx";
import { useModal } from "./use-modal";

type DrawerProps = {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  /** Small line above the title, e.g. the site. */
  context?: ReactNode;
  sub?: ReactNode;
  /** The "Record" line at the bottom of the body: who did what, and when. */
  record?: ReactNode;
  footer?: ReactNode;
  children: ReactNode;
};

export function Drawer({ open, onClose, title, context, sub, record, footer, children }: DrawerProps) {
  const panelRef = useModal(open, onClose);
  const titleId = useId();
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50">
      <div data-testid="drawer-scrim" aria-hidden="true" className="absolute inset-0 bg-[rgb(23_19_42/35%)]" onClick={onClose} />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className="absolute inset-y-0 right-0 flex w-[min(460px,100vw)] flex-col bg-(--paper) shadow-[-14px_0_34px_rgb(24_16_46/12%)] outline-none"
      >
        <header className="flex items-start gap-3 border-b border-(--line) px-5 py-4">
          <div className="grid min-w-0 flex-1 gap-0.5">
            {context ? <p className="m-0 text-xs text-(--muted)">{context}</p> : null}
            <h2 id={titleId} className="m-0 text-xl leading-[1.3] font-semibold break-words text-(--ink)">
              {title}
            </h2>
            {sub ? <p className="m-0 text-[13px] text-(--muted)">{sub}</p> : null}
          </div>
          <button
            type="button"
            aria-label="Close"
            onClick={onClose}
            className={cx("flex size-10 shrink-0 items-center justify-center rounded-lg text-(--slate) hover:bg-(--primary-tint)", focusRing)}
          >
            <X size={18} aria-hidden="true" />
          </button>
        </header>
        <div className="grid flex-1 content-start gap-5 overflow-y-auto px-5 py-5 text-sm text-(--slate)">
          {children}
          {record ? (
            <p className="m-0 border-t border-(--line) pt-4 text-xs text-(--muted)">
              <span className="font-semibold text-(--slate)">Record</span> · {record}
            </p>
          ) : null}
        </div>
        {footer ? <footer className="flex flex-wrap gap-2 border-t border-(--line) px-5 py-4">{footer}</footer> : null}
      </div>
    </div>
  );
}

/** Definition list used inside drawers and "At a glance" cards. */
export function DefinitionList({ items }: { items: Array<{ term: string; value: ReactNode }> }) {
  return (
    <dl className="m-0 grid grid-cols-[130px_1fr] gap-x-4 gap-y-2.5">
      {items.map(({ term, value }) => (
        <div key={term} className="contents">
          <dt className="text-[13px] text-(--muted)">{term}</dt>
          <dd className="m-0 min-w-0 break-words text-(--ink)">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Dark read-only code block (output, source, hashes). */
export function CodeBlock({ children, label }: { children: string; label?: string }) {
  return (
    <pre
      aria-label={label}
      tabIndex={0}
      className={cx("m-0 overflow-x-auto rounded-lg bg-(--ink-deep) p-4 font-(family-name:--font-data) text-[13px] leading-relaxed text-(--chrome-text)", focusRing)}
    >
      <code>{children}</code>
    </pre>
  );
}
