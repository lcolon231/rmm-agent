// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { ChevronDown, ChevronsUpDown, Plus, X } from "lucide-react";
import Image from "next/image";
import Link from "next/link";
import { useEffect, useState } from "react";

import type { NavigationData } from "@/lib/client-navigation";
import type { DashboardOperator } from "@/lib/dashboard-auth-core";

import { cx, focusRing } from "../ui/cx";
import { IntegrityCard, IntegrityRailMark } from "./integrity";
import type { NavGroup } from "./nav-groups";
import type { IntegrityView } from "./use-audit-integrity";

const GROUPS_KEY = "nodelink.nav-groups";
const chromeFocus = cx(focusRing, "focus-visible:outline-(--primary-on-dark)");

export type SidebarData = {
  groups: NavGroup[];
  activeHref: string | null;
  activeGroup: string | null;
  navigation: NavigationData | null;
  navigationError: boolean;
  operator: DashboardOperator;
  selectedClientId?: string;
  selectedSiteId?: string;
  selectionError?: boolean;
  supportUnread: number;
  integrity: IntegrityView;
};

function readGroups(): Record<string, boolean> {
  try {
    const parsed: unknown = JSON.parse(window.localStorage.getItem(GROUPS_KEY) ?? "{}");
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, boolean>) : {};
  } catch {
    return {};
  }
}

function writeGroups(value: Record<string, boolean>) {
  try {
    window.localStorage.setItem(GROUPS_KEY, JSON.stringify(value));
  } catch {
    /* storage blocked: groups just reset next visit */
  }
}

function Brand() {
  return (
    <Link href="/" className={cx("flex items-center gap-3 rounded-lg no-underline", chromeFocus)}>
      <Image src="/brand/nodelink-logo.jpg" alt="" width={32} height={32} className="size-8 rounded-lg" priority />
      <span className="grid leading-tight">
        <span className="text-base font-semibold text-(--chrome-text)">NodeLink</span>
        <span className="text-xs text-(--chrome-muted)">Operations</span>
      </span>
    </Link>
  );
}

function initials(name: string) {
  return name
    .split(/\s+/)
    .map((part) => part[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();
}

function ClientSwitcher({ data, onNavigate }: { data: SidebarData; onNavigate: () => void }) {
  const [open, setOpen] = useState(false);
  const { navigation, navigationError, operator, selectedClientId, selectedSiteId, selectionError } = data;
  const client = navigation?.items.find((item) => item.id === selectedClientId);
  const site = client?.sites.find((item) => item.id === selectedSiteId);
  const devices = (client ? [client] : (navigation?.items ?? [])).flatMap((item) => item.sites).reduce((sum, item) => sum + item.endpoint_count, 0);
  const title = client?.name ?? "All clients";
  const sub = `${site?.name ?? "All sites"} · ${devices} ${devices === 1 ? "device" : "devices"}`;

  if (navigationError) {
    return (
      <div role="alert" className="grid gap-2 rounded-[10px] bg-(--ink) p-3 text-[13px] text-(--chrome-text)">
        Client list is unavailable.
        <button type="button" onClick={() => window.location.reload()} className={cx("w-fit rounded-md bg-(--ink-soft) px-3 py-1 font-semibold", chromeFocus)}>
          Try again
        </button>
      </div>
    );
  }

  return (
    <div className="grid gap-1">
      <button
        type="button"
        aria-expanded={open}
        aria-controls="client-switcher-list"
        onClick={() => setOpen((value) => !value)}
        className={cx("flex w-full items-center gap-3 rounded-[10px] bg-(--ink) p-2.5 text-left hover:bg-(--chrome-hover)", chromeFocus)}
      >
        <span aria-hidden="true" className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-(--ink-soft) text-xs font-semibold text-(--chrome-text)">
          {client ? initials(client.name) : "All"}
        </span>
        <span className="grid min-w-0 flex-1">
          <span className="truncate font-semibold text-(--chrome-text)">{title}</span>
          <span className="truncate text-xs text-(--chrome-muted)">{sub}</span>
        </span>
        <ChevronsUpDown size={16} aria-hidden="true" className="text-(--chrome-muted)" />
      </button>
      {selectionError ? (
        <p role="alert" className="m-0 px-1 text-xs text-[#f2bd70]">
          The requested client or site is unavailable.
        </p>
      ) : null}
      {open ? (
        <div id="client-switcher-list" className="grid max-h-72 gap-0.5 overflow-y-auto rounded-[10px] border border-(--chrome-line) bg-(--ink) p-1.5">
          <SwitcherLink href="/" current={!selectedClientId} onNavigate={onNavigate}>
            All clients
          </SwitcherLink>
          {navigation?.items.length === 0 ? <p className="m-0 px-2 py-1.5 text-xs text-(--chrome-muted)">No clients are available to you.</p> : null}
          {navigation?.items.map((item) => (
            <div key={item.id} className="grid gap-0.5">
              <SwitcherLink href={`/?client=${encodeURIComponent(item.id)}`} current={selectedClientId === item.id && !selectedSiteId} onNavigate={onNavigate}>
                {item.name}
              </SwitcherLink>
              {item.sites.map((entry) => (
                <SwitcherLink
                  key={entry.id}
                  indent
                  href={`/?client=${encodeURIComponent(item.id)}&site=${encodeURIComponent(entry.id)}`}
                  current={selectedSiteId === entry.id}
                  count={entry.endpoint_count}
                  onNavigate={onNavigate}
                >
                  {entry.name}
                </SwitcherLink>
              ))}
            </div>
          ))}
          {navigation?.truncated ? <p className="m-0 px-2 py-1.5 text-xs text-(--chrome-muted)">Only the first 200 clients are shown.</p> : null}
          {operator.role !== "readonly" ? (
            <Link
              href="/enrollment/setup"
              onClick={onNavigate}
              className={cx("mt-1 flex items-center gap-2 rounded-md border-t border-(--chrome-line) px-2 py-2 text-[13px] text-(--chrome-text) no-underline hover:bg-(--chrome-hover)", chromeFocus)}
            >
              <Plus size={14} aria-hidden="true" />
              Add a client
            </Link>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function SwitcherLink({
  href,
  current,
  indent = false,
  count,
  onNavigate,
  children,
}: {
  href: string;
  current: boolean;
  indent?: boolean;
  count?: number;
  onNavigate: () => void;
  children: string;
}) {
  return (
    <Link
      href={href}
      onClick={onNavigate}
      aria-current={current ? "page" : undefined}
      className={cx(
        "flex items-center gap-2 rounded-md py-1.5 pr-2 text-[13px] no-underline hover:bg-(--chrome-hover)",
        indent ? "pl-6" : "pl-2",
        current ? "bg-(--ink-soft) font-semibold text-white" : "text-(--chrome-text)",
        chromeFocus,
      )}
    >
      <span className="min-w-0 flex-1 truncate">{children}</span>
      {count !== undefined ? <span className="text-xs text-(--chrome-muted) tabular-nums">{count}</span> : null}
    </Link>
  );
}

function CountPill({ value, label }: { value: number; label: string }) {
  if (value <= 0) return null;
  return (
    <span className="ml-auto rounded-full bg-(--ink-soft) px-2 py-0.5 text-xs font-semibold text-(--chrome-text) tabular-nums">
      {value}
      <span className="sr-only"> {label}</span>
    </span>
  );
}

function itemCount(href: string, data: SidebarData) {
  return href === "/support" ? data.supportUnread : 0;
}

function NavGroups({ data, onNavigate }: { data: SidebarData; onNavigate: () => void }) {
  // Server render and first paint: only the current group is open. Stored
  // preferences apply after mount so hydration matches.
  const [stored, setStored] = useState<Record<string, boolean>>({});
  useEffect(() => {
    queueMicrotask(() => setStored(readGroups()));
  }, []);

  function toggle(id: string) {
    setStored((previous) => {
      const next = { ...previous, [id]: !previous[id] };
      writeGroups(next);
      return next;
    });
  }

  return (
    <nav aria-label="Primary" className="grid gap-1">
      {data.groups.map((group) => {
        const Icon = group.icon;
        if (group.href) {
          const active = data.activeHref === group.href;
          return (
            <Link
              key={group.id}
              href={group.href}
              onClick={onNavigate}
              aria-current={active ? "page" : undefined}
              className={cx(
                "flex h-9 items-center gap-3 rounded-lg px-3 text-sm no-underline",
                active ? "bg-(--ink-soft) font-semibold text-white" : "font-semibold text-(--chrome-muted) hover:bg-(--chrome-hover) hover:text-(--chrome-text)",
                chromeFocus,
              )}
            >
              <Icon size={16} aria-hidden="true" />
              {group.label}
            </Link>
          );
        }
        const isCurrent = data.activeGroup === group.id;
        const open = isCurrent || Boolean(stored[group.id]);
        const listId = `nav-group-${group.id}`;
        const hiddenCount = open ? 0 : group.items.reduce((sum, item) => sum + itemCount(item.href, data), 0);
        return (
          <div key={group.id} className="grid gap-0.5">
            <button
              type="button"
              aria-expanded={open}
              aria-controls={listId}
              onClick={() => {
                if (!isCurrent) toggle(group.id);
              }}
              className={cx(
                "flex h-9 w-full items-center gap-3 rounded-lg px-3 text-left text-[13px] font-semibold hover:bg-(--chrome-hover)",
                isCurrent ? "text-(--chrome-text)" : "text-(--chrome-muted)",
                chromeFocus,
              )}
            >
              <Icon size={16} aria-hidden="true" />
              <span className="flex-1">{group.label}</span>
              <CountPill value={hiddenCount} label="unread" />
              <ChevronDown size={16} aria-hidden="true" className={cx("text-(--chrome-muted)", open && "rotate-180")} />
            </button>
            <ul id={listId} hidden={!open} className="m-0 grid list-none gap-0.5 p-0">
              {group.items.map((item) => {
                const active = data.activeHref === item.href;
                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      onClick={onNavigate}
                      aria-current={active ? "page" : undefined}
                      className={cx(
                        "flex h-9 items-center gap-2 rounded-lg pr-3 pl-9 text-sm no-underline",
                        active ? "bg-(--ink-soft) font-semibold text-white" : "text-(--chrome-text) hover:bg-(--chrome-hover)",
                        chromeFocus,
                      )}
                    >
                      <span className="flex-1">{item.label}</span>
                      <CountPill value={itemCount(item.href, data)} label="unread" />
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        );
      })}
    </nav>
  );
}

/** Full 272px sidebar: brand, client switcher, grouped navigation, integrity card. */
export function SidebarFull({ data, onNavigate, onClose }: { data: SidebarData; onNavigate: () => void; onClose?: () => void }) {
  return (
    <div className="flex h-full w-[272px] flex-col bg-(--ink-deep)">
      <div className="flex h-16 shrink-0 items-center justify-between px-4">
        <Brand />
        {onClose ? (
          <button
            type="button"
            aria-label="Close navigation"
            onClick={onClose}
            className={cx("flex size-10 items-center justify-center rounded-lg text-(--chrome-text) hover:bg-(--chrome-hover)", chromeFocus)}
          >
            <X size={18} aria-hidden="true" />
          </button>
        ) : null}
      </div>
      <div className="grid flex-1 content-start gap-4 overflow-y-auto px-3 pb-4">
        <ClientSwitcher data={data} onNavigate={onNavigate} />
        <NavGroups data={data} onNavigate={onNavigate} />
      </div>
      <div className="shrink-0 p-3">
        <IntegrityCard view={data.integrity} />
      </div>
    </div>
  );
}

/** 64px icon rail. Any group icon opens the full sidebar as an overlay. */
export function SidebarRail({ data, onExpand }: { data: SidebarData; onExpand: () => void }) {
  return (
    <div className="flex h-full w-16 flex-col items-center gap-1 bg-(--ink-deep) py-3">
      <Link href="/" className={cx("mb-3 rounded-lg", chromeFocus)} title="NodeLink Operations">
        <Image src="/brand/nodelink-logo.jpg" alt="NodeLink Operations" width={32} height={32} className="size-8 rounded-lg" priority />
      </Link>
      <nav aria-label="Primary" className="grid gap-1">
        {data.groups.map((group) => {
          const Icon = group.icon;
          const current = data.activeGroup === group.id;
          const className = cx(
            "relative flex size-10 items-center justify-center rounded-lg",
            current ? "bg-(--ink-soft) text-white" : "text-(--chrome-muted) hover:bg-(--chrome-hover) hover:text-(--chrome-text)",
            chromeFocus,
          );
          const unread = group.items.reduce((sum, item) => sum + itemCount(item.href, data), 0);
          return group.href ? (
            <Link key={group.id} href={group.href} title={group.label} aria-current={data.activeHref === group.href ? "page" : undefined} className={className}>
              <Icon size={18} aria-hidden="true" />
              <span className="sr-only">{group.label}</span>
            </Link>
          ) : (
            <button key={group.id} type="button" title={group.label} aria-label={`${group.label}${unread ? `, ${unread} unread` : ""}`} onClick={onExpand} className={className}>
              <Icon size={18} aria-hidden="true" />
              {unread ? <span aria-hidden="true" className="absolute top-1.5 right-1.5 size-2 rounded-full bg-(--primary-on-dark)" /> : null}
            </button>
          );
        })}
      </nav>
      <div className="mt-auto">
        <IntegrityRailMark view={data.integrity} />
      </div>
    </div>
  );
}
