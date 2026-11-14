// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { usePathname } from "next/navigation";
import { useEffect, useMemo, useState, type ReactNode } from "react";

import type { NavigationData } from "@/lib/client-navigation";
import type { DashboardOperator } from "@/lib/dashboard-auth-core";

import { AssistantWidget } from "../assistant/assistant-widget";
import { useModal } from "../ui/use-modal";
import { anchorLine, IntegrityHeadline } from "./integrity";
import { activeHref as findActiveHref, groupForHref, visibleGroups } from "./nav-groups";
import { SidebarFull, SidebarRail, type SidebarData } from "./sidebar";
import { TopBar } from "./top-bar";
import { useAuditIntegrity, type IntegrityView } from "./use-audit-integrity";

const COLLAPSED_KEY = "nodelink.sidebar-collapsed";
const WIDE_QUERY = "(min-width: 1100px)";

export type AppShellProps = {
  /** Fallback when the router pathname is unavailable (tests, error pages). */
  activePath: string;
  navigation: NavigationData | null;
  navigationError: boolean;
  operator: DashboardOperator;
  selectedClientId?: string;
  selectedSiteId?: string;
  selectionError?: boolean;
  alertCount?: number;
  /** Assistant pilot state from `getAssistantContext`; omit to leave the floating assistant off. */
  assistantState?: string;
  children: ReactNode;
};

function useSupportUnread() {
  // Poll the cheap unread-count route so the Support chat badge stays current
  // without a full navigation refresh.
  const [unread, setUnread] = useState(0);
  useEffect(() => {
    let stopped = false;
    async function poll() {
      try {
        const response = await fetch("/api/support/unread-count", { cache: "no-store" });
        if (response.ok) {
          const data = await response.json();
          if (!stopped && Number.isInteger(data?.unread)) setUnread(data.unread);
        }
      } catch {
        /* transient; next tick retries */
      }
    }
    void poll();
    const timer = setInterval(poll, 10000);
    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, []);
  return unread;
}

function formatClock(date: Date) {
  return new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit" }).format(date);
}

/** Identical on every page: integrity, last anchor, who is signed in and when the page loaded. */
export function RecordFooter({ integrity, operatorEmail }: { integrity: IntegrityView; operatorEmail: string }) {
  // Set after mount so the server render and first client paint agree.
  const [loadedAt, setLoadedAt] = useState<string | null>(null);
  useEffect(() => {
    queueMicrotask(() => setLoadedAt(formatClock(new Date())));
  }, []);
  return (
    <footer className="mt-8 flex flex-wrap items-center gap-x-2 gap-y-1 border-t border-(--line) pt-4 text-xs text-(--muted)">
      <IntegrityHeadline view={integrity} tone="light" />
      <span aria-hidden="true">·</span>
      <span>{anchorLine(integrity)}</span>
      <span aria-hidden="true">·</span>
      <span>
        Signed in as <span className="font-(family-name:--font-data)">{operatorEmail}</span>
        {loadedAt ? ` · page loaded ${loadedAt}` : null}
      </span>
    </footer>
  );
}

function NavOverlay({ data, onClose }: { data: SidebarData; onClose: () => void }) {
  const panelRef = useModal(true, onClose);
  return (
    <div className="fixed inset-0 z-50">
      <div aria-hidden="true" className="absolute inset-0 bg-[rgb(23_19_42/35%)]" onClick={onClose} />
      <div ref={panelRef} role="dialog" aria-modal="true" aria-label="Navigation" className="absolute inset-y-0 left-0 shadow-[14px_0_34px_rgb(24_16_46/12%)]">
        <SidebarFull data={data} onNavigate={onClose} onClose={onClose} />
      </div>
    </div>
  );
}

export function AppShell({
  activePath,
  navigation,
  navigationError,
  operator,
  selectedClientId,
  selectedSiteId,
  selectionError = false,
  alertCount,
  assistantState,
  children,
}: AppShellProps) {
  const pathname = usePathname() ?? activePath;
  const integrity = useAuditIntegrity();
  const supportUnread = useSupportUnread();
  const [overlayOpen, setOverlayOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const [signOutError, setSignOutError] = useState("");

  useEffect(() => {
    queueMicrotask(() => {
      try {
        setCollapsed(window.localStorage.getItem(COLLAPSED_KEY) === "1");
      } catch {
        /* storage blocked: start expanded */
      }
    });
  }, []);

  const groups = useMemo(() => visibleGroups(operator.role), [operator.role]);
  const active = findActiveHref(pathname, groups);
  const client = navigation?.items.find((item) => item.id === selectedClientId);
  const assistantClients = useMemo(() => navigation?.items.map(({ id, name }) => ({ id, name })) ?? [], [navigation]);
  const site = client?.sites.find((item) => item.id === selectedSiteId);

  const data: SidebarData = {
    groups,
    activeHref: active,
    activeGroup: groupForHref(active, groups),
    navigation,
    navigationError,
    operator,
    selectedClientId,
    selectedSiteId,
    selectionError,
    supportUnread,
    integrity,
  };

  function toggleNav() {
    if (window.matchMedia(WIDE_QUERY).matches) {
      setCollapsed((value) => {
        try {
          window.localStorage.setItem(COLLAPSED_KEY, value ? "0" : "1");
        } catch {
          /* storage blocked: preference lasts this page only */
        }
        return !value;
      });
    } else {
      setOverlayOpen(true);
    }
  }

  async function signOut() {
    setSignOutError("");
    try {
      await fetch("/api/auth/logout", { method: "POST" });
      window.location.assign("/login");
    } catch {
      setSignOutError("Sign-out could not be confirmed. Try again.");
    }
  }

  return (
    <div className="flex min-h-screen bg-(--fog) text-sm text-(--slate)">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[70] focus:rounded-lg focus:bg-(--paper) focus:px-4 focus:py-2 focus:font-semibold focus:text-(--primary-strong)"
      >
        Skip to content
      </a>
      <aside aria-label="Sidebar" className="sticky top-0 hidden h-screen shrink-0 border-r border-(--chrome-line) min-[720px]:block">
        {collapsed ? (
          <SidebarRail data={data} onExpand={() => setOverlayOpen(true)} />
        ) : (
          <>
            <div className="h-full min-[1100px]:hidden">
              <SidebarRail data={data} onExpand={() => setOverlayOpen(true)} />
            </div>
            <div className="hidden h-full min-[1100px]:block">
              <SidebarFull data={data} onNavigate={() => {}} />
            </div>
          </>
        )}
      </aside>
      {overlayOpen ? <NavOverlay data={data} onClose={() => setOverlayOpen(false)} /> : null}
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar
          operator={operator}
          scope={{ client: client?.name ?? "All clients", site: site?.name ?? "All sites" }}
          navExpanded={overlayOpen || !collapsed}
          onToggleNav={toggleNav}
          alertCount={alertCount}
          onSignOut={signOut}
        />
        <main id="main-content" tabIndex={-1} className="mx-auto w-full max-w-[1360px] flex-1 px-4 pt-6 pb-8 outline-none min-[720px]:px-8">
          {signOutError ? (
            <p role="alert" className="mt-0 mb-4 rounded-lg bg-(--red-soft) px-3 py-2 text-(--red)">
              {signOutError}
            </p>
          ) : null}
          {children}
          <RecordFooter integrity={integrity} operatorEmail={operator.email} />
        </main>
      </div>
      {assistantState !== undefined ? <AssistantWidget clients={assistantClients} state={assistantState} pathname={pathname} /> : null}
    </div>
  );
}
