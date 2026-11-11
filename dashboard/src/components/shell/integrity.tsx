// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { CircleAlert, CircleHelp, Loader, ShieldCheck, type LucideIcon } from "lucide-react";
import Link from "next/link";

import { formatAnchorTime } from "@/lib/audit-integrity-core";

import { cx } from "../ui/cx";
import type { IntegrityView } from "./use-audit-integrity";

type Copy = { icon: LucideIcon; headline: string; light: string; dark: string };

const COPY: Record<IntegrityView["chain"], Copy> = {
  checking: { icon: Loader, headline: "Checking audit record…", light: "text-(--muted)", dark: "text-(--chrome-muted)" },
  intact: { icon: ShieldCheck, headline: "Audit record intact", light: "text-(--success)", dark: "text-(--success-on-dark)" },
  failed: { icon: CircleAlert, headline: "Audit record check failed", light: "text-(--red)", dark: "text-[#f3a5a5]" },
  unknown: { icon: CircleHelp, headline: "Audit record not verified", light: "text-[#89500b]", dark: "text-[#f2bd70]" },
};

export function anchorLine(view: IntegrityView): string {
  if (view.chain === "checking") return "Last integrity anchor loading";
  return view.last_anchor_at ? `Last integrity anchor ${formatAnchorTime(view.last_anchor_at)}` : "No integrity anchor yet";
}

/** Headline with icon. A failed chain is an alert; everything else a status. */
export function IntegrityHeadline({ view, tone }: { view: IntegrityView; tone: "light" | "dark" }) {
  const { icon: Icon, headline, light, dark } = COPY[view.chain];
  return (
    <span role={view.chain === "failed" ? "alert" : undefined} className={cx("inline-flex items-center gap-1.5 font-semibold", tone === "light" ? light : dark)}>
      <Icon size={16} aria-hidden="true" />
      {headline}
    </span>
  );
}

/** Sidebar footer card on the dark chrome. */
export function IntegrityCard({ view }: { view: IntegrityView }) {
  return (
    <div aria-live="polite" className="grid gap-1 rounded-[10px] border border-(--chrome-line) bg-(--ink) p-3 text-[13px]">
      <IntegrityHeadline view={view} tone="dark" />
      <span className="text-xs text-(--chrome-muted)">{anchorLine(view)}</span>
      {view.chain === "failed" || view.chain === "unknown" ? (
        <Link href="/audit" className="text-xs font-semibold text-(--chrome-text) underline underline-offset-2">
          Open audit log
        </Link>
      ) : null}
    </div>
  );
}

/** Icon-only form for the collapsed rail; the words stay available to screen readers. */
export function IntegrityRailMark({ view }: { view: IntegrityView }) {
  const { icon: Icon, headline, dark } = COPY[view.chain];
  return (
    <Link href="/audit" title={headline} className={cx("flex size-10 items-center justify-center rounded-lg hover:bg-(--chrome-hover)", dark)}>
      <Icon size={18} aria-hidden="true" />
      <span className="sr-only">{headline}</span>
    </Link>
  );
}
