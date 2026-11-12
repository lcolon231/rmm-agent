// SPDX-License-Identifier: AGPL-3.0-only

import { Info } from "lucide-react";
import type { ReactNode } from "react";

import { cx } from "../ui/cx";
import { cardClass } from "../ui/stat-tile";

/** Page description shared by the queue and a single conversation. Verified
 * against the server: an end user's first message is refused until the
 * recording notice is acknowledged. */
export const SUPPORT_DESCRIPTION =
  "Conversations with people on endpoints you can see. The user must accept a recording notice before they can send a message.";

/**
 * Shared layout for Support chat and the AI assistant: a list pane (max 360px)
 * and a thread pane that wrap onto separate rows on narrow screens.
 */
export function ChatPanes({ list, children }: { list: ReactNode; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-start gap-4">
      <div className="min-w-0 grow basis-[300px] min-[900px]:max-w-[360px]">{list}</div>
      <div className="min-w-0 grow-[999] basis-[420px]">{children}</div>
    </div>
  );
}

/** Card surface for either pane. */
export function ChatCard({ label, className, children }: { label?: string; className?: string; children: ReactNode }) {
  return (
    <section aria-label={label} className={cx(cardClass, "overflow-hidden", className)}>
      {children}
    </section>
  );
}

/** Thread header: title, optional status, one context line, optional actions. */
export function ThreadHeader({ title, status, context, actions }: {
  title: ReactNode; status?: ReactNode; context?: ReactNode; actions?: ReactNode;
}) {
  return (
    <header className="flex flex-wrap items-start justify-between gap-3 border-b border-(--line) px-5 py-4">
      <div className="grid min-w-0 gap-1">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="m-0 text-base font-semibold break-words text-(--ink)">{title}</h2>
          {status}
        </div>
        {context ? <p className="m-0 text-[13px] text-(--muted)">{context}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </header>
  );
}

/** Quiet notice above the composer. */
export function ChatNotice({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-start gap-2 border-t border-(--line) bg-(--fog) px-5 py-3 text-[13px] text-(--slate)">
      <Info size={16} aria-hidden="true" className="mt-0.5 shrink-0 text-(--muted)" />
      <div className="grid gap-1">{children}</div>
    </div>
  );
}

export type BubbleSide = "mine" | "theirs" | "system";

/** Classes for a message list item. Bodies always render as text. */
export function bubbleClass(side: BubbleSide) {
  if (side === "system") {
    return "self-center max-w-[min(560px,88%)] rounded-[10px] border border-(--line) bg-(--paper) px-3.5 py-2 text-center text-[13px] text-(--muted)";
  }
  return cx(
    "max-w-[min(560px,88%)] rounded-[10px] px-3.5 py-2.5 text-sm text-(--ink) [overflow-wrap:anywhere]",
    side === "mine" ? "self-end bg-(--primary-soft)" : "self-start bg-(--fog)",
  );
}

/** "who · time" line above a bubble. */
export function BubbleMeta({ who, time, dateTime }: { who: ReactNode; time?: string; dateTime?: string }) {
  return (
    <p className="m-0 mb-1 text-xs text-(--muted)">
      <strong className="font-semibold text-(--slate)">{who}</strong>
      {time ? <> · <time dateTime={dateTime}>{time}</time></> : null}
    </p>
  );
}

/** Scrollable message column. */
export const messageListClass = "m-0 flex max-h-[55vh] min-h-[240px] list-none flex-col gap-3 overflow-y-auto p-5";

/** Unread count pill; the number is also announced in words. */
export function UnreadPill({ count }: { count: number }) {
  return (
    <span className="inline-flex min-w-6 items-center justify-center rounded-full bg-(--primary-strong) px-2 text-xs leading-5 font-semibold text-white">
      {count}
      <span className="sr-only"> unread</span>
    </span>
  );
}
