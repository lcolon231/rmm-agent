// SPDX-License-Identifier: AGPL-3.0-only

import { ChevronLeft, ChevronRight, type LucideIcon } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { PageHeader, type Crumb } from "../shell/page-header";
import { cx, focusRing } from "../ui/cx";
import { cardClass } from "../ui/stat-tile";
import { toneStyles, type StatusTone } from "../ui/status-badge";
import { TabNav } from "../ui/tab-nav";

export type EndpointSection = "summary" | "inventory" | "commands" | "remote";

const SECTION_LABELS: Record<EndpointSection, string> = {
  summary: "Summary",
  inventory: "Inventory",
  commands: "Commands",
  remote: "Remote access",
};

export function endpointBase(endpointId: string) {
  return `/endpoints/${encodeURIComponent(endpointId)}`;
}

/** Devices › Endpoints › hostname, the trail every device page starts with. */
export function endpointCrumbs(endpointId: string, hostname: string): Crumb[] {
  return [{ label: "Devices" }, { label: "Endpoints", href: "/endpoints" }, { label: hostname, href: endpointBase(endpointId) }];
}

/** The same "Device sections" tabs the endpoint detail page shows. */
export function EndpointSectionTabs({ endpointId, current }: { endpointId: string; current: EndpointSection }) {
  const base = endpointBase(endpointId);
  return (
    <TabNav
      label="Device sections"
      tabs={[
        { label: "Summary", href: base, current: current === "summary" },
        { label: "Inventory", href: `${base}/inventory`, current: current === "inventory" },
        { label: "Commands", href: `${base}/commands`, current: current === "commands" },
        { label: "Remote access", href: `${base}?tab=remote`, current: current === "remote" },
      ]}
    />
  );
}

type EndpointSectionHeaderProps = {
  endpointId: string;
  hostname: string;
  section: Exclude<EndpointSection, "summary" | "remote">;
  /** Extra trail after the section, e.g. one inventory section. */
  trail?: Crumb[];
  description?: ReactNode;
  actions?: ReactNode;
};

/** Header for a device subpage: breadcrumb, hostname in mono, then the device tabs. */
export function EndpointSectionHeader({ endpointId, hostname, section, trail = [], description, actions }: EndpointSectionHeaderProps) {
  const sectionCrumb: Crumb = trail.length ? { label: SECTION_LABELS[section], href: `${endpointBase(endpointId)}/${section}` } : { label: SECTION_LABELS[section] };
  return (
    <>
      <PageHeader
        breadcrumb={[...endpointCrumbs(endpointId, hostname), sectionCrumb, ...trail]}
        title={<span className="font-(family-name:--font-data)">{hostname}</span>}
        description={description}
        actions={actions}
      />
      <EndpointSectionTabs endpointId={endpointId} current={section} />
    </>
  );
}

/** Card with a titled header row; the building block of every subpage. */
export function Panel({ title, sub, action, id, children, className }: { title: ReactNode; sub?: ReactNode; action?: ReactNode; id?: string; children: ReactNode; className?: string }) {
  return (
    <section id={id} aria-label={typeof title === "string" ? title : undefined} className={cx(cardClass, "overflow-hidden", className)}>
      <header className="flex flex-wrap items-start justify-between gap-3 border-b border-(--line) px-5 py-4">
        <div className="grid min-w-0 gap-0.5">
          <h2 className="m-0 text-base font-semibold text-(--ink)">{title}</h2>
          {sub ? <p className="m-0 text-xs text-(--muted)">{sub}</p> : null}
        </div>
        {action}
      </header>
      {children}
    </section>
  );
}

/** Status note: tone background, icon, bold line and one sentence. */
export function Notice({ tone, title, children, role = "status", icon, action }: { tone: StatusTone; title: ReactNode; children?: ReactNode; role?: "status" | "alert" | "note"; icon?: LucideIcon; action?: ReactNode }) {
  const { surface, text, icon: ToneIcon } = toneStyles[tone];
  const Icon = icon ?? ToneIcon;
  return (
    <div role={role} className={cx("flex flex-wrap items-start gap-3 rounded-[10px] px-4 py-3 text-sm", surface)}>
      <Icon size={18} aria-hidden="true" className={cx("mt-0.5 shrink-0", text)} />
      <p className="m-0 grid min-w-0 flex-1 gap-0.5">
        <strong className={cx("font-semibold", text)}>{title}</strong>
        {children ? <span className="text-(--slate)">{children}</span> : null}
      </p>
      {action}
    </div>
  );
}

/** A failure rendered inside the app shell: a section, never a second <main>. */
export function PageFailure({ eyebrow, title, body, children }: { eyebrow: string; title: string; body: string; children?: ReactNode }) {
  return (
    <section role="alert" className="grid max-w-[640px] gap-2 rounded-[10px] border border-(--line) bg-(--paper) p-6">
      <span className="text-xs text-(--muted)">{eyebrow}</span>
      <h1 className="m-0 text-2xl font-semibold text-(--ink)">{title}</h1>
      <p className="m-0 text-sm text-(--slate)">{body}</p>
      {children ? <p className="m-0 mt-2 flex flex-wrap gap-4 text-sm font-semibold">{children}</p> : null}
    </section>
  );
}

const pagerLink = "flex h-9 items-center gap-1 rounded-lg border border-(--line-strong) bg-(--paper) px-3 text-(--slate) no-underline hover:bg-(--primary-tint)";
const pagerOff = "flex h-9 items-center gap-1 rounded-lg border border-(--line) bg-(--fog) px-3 text-(--muted)";

/** URL-driven Newer / Older links for newest-first history. */
/** Without a label it renders bare, for use inside TableFooter's own nav. */
export function HistoryPager({ label, page, pages, newerHref, olderHref }: { label?: string; page: number; pages?: number; newerHref: string | null; olderHref: string | null }) {
  const Wrapper = label ? "nav" : "span";
  return (
    <Wrapper aria-label={label} className="flex items-center gap-1 text-xs">
      {newerHref ? (
        <Link href={newerHref} rel="prev" className={cx(pagerLink, focusRing)}>
          <ChevronLeft size={14} aria-hidden="true" /> Newer
        </Link>
      ) : (
        <span aria-hidden="true" className={pagerOff}>
          <ChevronLeft size={14} /> Newer
        </span>
      )}
      <span className="px-2">{pages ? `Page ${page} of ${pages}` : `Page ${page}`}</span>
      {olderHref ? (
        <Link href={olderHref} rel="next" className={cx(pagerLink, focusRing)}>
          Older <ChevronRight size={14} aria-hidden="true" />
        </Link>
      ) : (
        <span aria-hidden="true" className={pagerOff}>
          Older <ChevronRight size={14} />
        </span>
      )}
    </Wrapper>
  );
}

export const inlineLink = cx("rounded font-semibold text-(--primary-strong) no-underline hover:underline", focusRing);
export const monoText = "font-(family-name:--font-data) text-[13px]";
