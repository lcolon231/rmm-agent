// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { Bell, KeyRound, LogOut, PanelLeft, Search } from "lucide-react";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import type { DashboardOperator } from "@/lib/dashboard-auth-core";
import { operatorRoleLabel } from "@/lib/operator-management-core";

import { cx, focusRing } from "../ui/cx";

type TopBarProps = {
  operator: DashboardOperator;
  scope: { client: string; site: string };
  navExpanded: boolean;
  onToggleNav: () => void;
  /** Open alerts, when the page already knows it; never guessed. */
  alertCount?: number;
  onSignOut: () => void;
};

export function operatorInitials(email: string) {
  return email
    .split("@")[0]
    .split(/[._-]/)
    .map((part) => part[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();
}

function OperatorMenu({ operator, onSignOut }: { operator: DashboardOperator; onSignOut: () => void }) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onPointer(event: PointerEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    }
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }
    document.addEventListener("pointerdown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const role = operatorRoleLabel(operator.role);
  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        aria-expanded={open}
        aria-controls="operator-menu"
        aria-label={`Account: ${operator.email}, ${role}`}
        onClick={() => setOpen((value) => !value)}
        className={cx("flex items-center gap-2.5 rounded-lg p-1 pr-2 text-left hover:bg-(--primary-tint)", focusRing)}
      >
        <span aria-hidden="true" className="flex size-8 items-center justify-center rounded-full bg-(--primary-soft) text-xs font-semibold text-(--primary-press)">
          {operatorInitials(operator.email)}
        </span>
        <span aria-hidden="true" className="hidden max-w-[220px] min-[1100px]:grid">
          <span className="truncate text-[13px] font-semibold text-(--ink)">{operator.email}</span>
          <span className="text-xs text-(--muted)">{role}</span>
        </span>
      </button>
      {open ? (
        <div id="operator-menu" className="absolute top-[calc(100%+6px)] right-0 z-40 grid w-60 gap-0.5 rounded-[10px] border border-(--line) bg-(--paper) p-1.5 shadow-[0_14px_34px_rgb(24_16_46/12%)]">
          <p className="m-0 grid border-b border-(--line) px-2.5 pt-1.5 pb-2.5">
            <span className="truncate text-[13px] font-semibold text-(--ink)">{operator.email}</span>
            <span className="text-xs text-(--muted)">{role}</span>
          </p>
          <Link
            href="/security"
            onClick={() => setOpen(false)}
            className={cx("flex h-9 items-center gap-2 rounded-md px-2.5 text-sm text-(--slate) no-underline hover:bg-(--primary-tint)", focusRing)}
          >
            <KeyRound size={16} aria-hidden="true" />
            Security keys and MFA
          </Link>
          <button
            type="button"
            onClick={onSignOut}
            className={cx("flex h-9 items-center gap-2 rounded-md px-2.5 text-left text-sm text-(--slate) hover:bg-(--primary-tint)", focusRing)}
          >
            <LogOut size={16} aria-hidden="true" />
            Sign out
          </button>
        </div>
      ) : null}
    </div>
  );
}

export function TopBar({ operator, scope, navExpanded, onToggleNav, alertCount, onSignOut }: TopBarProps) {
  return (
    <header className="sticky top-0 z-30 flex h-16 items-center gap-3 border-b border-(--line) bg-(--paper) px-4 min-[720px]:px-6">
      <button
        type="button"
        aria-label={navExpanded ? "Collapse navigation" : "Show navigation"}
        aria-expanded={navExpanded}
        onClick={onToggleNav}
        className={cx("flex size-10 shrink-0 items-center justify-center rounded-lg text-(--slate) hover:bg-(--primary-tint)", focusRing)}
      >
        <PanelLeft size={18} aria-hidden="true" />
      </button>
      <p className="m-0 hidden shrink-0 text-[13px] text-(--muted) min-[560px]:block">
        <span className="hidden min-[1100px]:inline">Viewing · </span>
        <span className="font-semibold text-(--ink)">{scope.client}</span> · {scope.site}
      </p>
      <form role="search" action="/endpoints" method="get" className="relative min-w-[160px] max-w-[480px] flex-1 min-[720px]:min-w-[200px]">
        <Search size={16} aria-hidden="true" className="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-(--muted)" />
        <input
          type="search"
          name="search"
          maxLength={100}
          aria-label="Search devices"
          placeholder="Search devices"
          className={cx("h-10 w-full rounded-lg border border-transparent bg-(--fog) pr-3 pl-9 text-sm text-(--ink) focus:border-(--line-strong) focus:bg-(--paper)", focusRing)}
        />
      </form>
      <div className="flex-1" />
      <Link
        href="/alerts"
        aria-label={alertCount ? `Alerts, ${alertCount} open` : "Alerts"}
        className={cx("relative flex size-10 shrink-0 items-center justify-center rounded-lg text-(--slate) hover:bg-(--primary-tint)", focusRing)}
      >
        <Bell size={18} aria-hidden="true" />
        {alertCount ? (
          <span aria-hidden="true" className="absolute top-1 right-1 min-w-[18px] rounded-full bg-(--red) px-1 text-center text-xs leading-[18px] font-semibold text-white">
            {alertCount > 99 ? "99+" : alertCount}
          </span>
        ) : null}
      </Link>
      <OperatorMenu operator={operator} onSignOut={onSignOut} />
    </header>
  );
}
