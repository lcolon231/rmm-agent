// SPDX-License-Identifier: AGPL-3.0-only

import {
  ClipboardCheck,
  LayoutDashboard,
  MessagesSquare,
  Monitor,
  Settings,
  Shield,
  Terminal,
  type LucideIcon,
} from "lucide-react";

import type { DashboardRole } from "@/lib/dashboard-auth-core";

export type NavItem = { label: string; href: string; adminOnly?: boolean };
export type NavGroup = { id: string; label: string; icon: LucideIcon; href?: string; items: NavItem[] };

/** The seven sidebar groups from the redesign handoff, mapped to existing routes. */
export const NAV_GROUPS: readonly NavGroup[] = [
  { id: "overview", label: "Overview", icon: LayoutDashboard, href: "/", items: [] },
  {
    id: "devices",
    label: "Devices",
    icon: Monitor,
    items: [
      { label: "Endpoints", href: "/endpoints" },
      { label: "Alerts", href: "/alerts" },
      { label: "Monitoring", href: "/monitoring" },
    ],
  },
  {
    id: "patching",
    label: "Patching",
    icon: Shield,
    items: [
      { label: "Patch compliance", href: "/patch-compliance" },
      { label: "Patch policies", href: "/patch-policies" },
      { label: "Maintenance windows", href: "/maintenance-windows" },
    ],
  },
  {
    id: "automation",
    label: "Automation",
    icon: Terminal,
    items: [
      { label: "Script library", href: "/scripts" },
      { label: "Community scripts", href: "/community" },
      { label: "Tasks", href: "/tasks" },
      { label: "Schedules", href: "/schedules" },
    ],
  },
  {
    id: "support",
    label: "Support",
    icon: MessagesSquare,
    items: [{ label: "Support chat", href: "/support" }],
  },
  {
    id: "compliance",
    label: "Compliance",
    icon: ClipboardCheck,
    items: [
      { label: "Approvals", href: "/approvals" },
      { label: "Audit", href: "/audit" },
      { label: "Emergency overrides", href: "/emergency-overrides" },
    ],
  },
  {
    id: "administration",
    label: "Administration",
    icon: Settings,
    items: [
      { label: "Enrollment", href: "/enrollment" },
      { label: "Operators", href: "/operators", adminOnly: true },
      { label: "Security keys and MFA", href: "/security" },
      { label: "Break-glass", href: "/security/break-glass", adminOnly: true },
    ],
  },
];

/** Groups and items this role may see; a group left with no items is dropped. */
export function visibleGroups(role: DashboardRole): NavGroup[] {
  return NAV_GROUPS.map((group) => ({
    ...group,
    items: group.items.filter((item) => !item.adminOnly || role === "admin"),
  })).filter((group) => group.href || group.items.length > 0);
}

function matches(path: string, href: string) {
  if (href === "/") return path === "/";
  return path === href || path.startsWith(`${href}/`);
}

/**
 * The single active destination for a path: the longest matching href, so
 * `/security/break-glass` lights Break-glass, not also Security keys.
 */
export function activeHref(path: string, groups: readonly NavGroup[]): string | null {
  let best: string | null = null;
  for (const group of groups) {
    const hrefs = group.href ? [group.href] : group.items.map((item) => item.href);
    for (const href of hrefs) {
      if (matches(path, href) && (best === null || href.length > best.length)) best = href;
    }
  }
  return best;
}

export function groupForHref(href: string | null, groups: readonly NavGroup[]): string | null {
  if (href === null) return null;
  return groups.find((group) => group.href === href || group.items.some((item) => item.href === href))?.id ?? null;
}
