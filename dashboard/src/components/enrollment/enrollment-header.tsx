// SPDX-License-Identifier: AGPL-3.0-only

import type { ReactNode } from "react";

import { PageHeader, type Crumb } from "@/components/shell/page-header";
import { TabNav } from "@/components/ui/tab-nav";
import type { DashboardRole } from "@/lib/dashboard-auth-core";

export type EnrollmentTab = "overview" | "agents" | "tokens" | "installer" | "setup" | "audit";

const TABS: Array<{ key: EnrollmentTab; label: string; href: string; manageOnly?: boolean }> = [
  { key: "overview", label: "Overview", href: "/enrollment" },
  { key: "agents", label: "Agents", href: "/enrollment/agents" },
  { key: "tokens", label: "Tokens", href: "/enrollment/tokens" },
  // Read-only operators are redirected away from these two, so they are not offered.
  { key: "installer", label: "Installer", href: "/enrollment/installer", manageOnly: true },
  { key: "setup", label: "Client setup", href: "/enrollment/setup", manageOnly: true },
  { key: "audit", label: "Activity", href: "/enrollment/audit" },
];

export function enrollmentTabs(current: EnrollmentTab, role: DashboardRole) {
  return TABS.filter((tab) => !tab.manageOnly || role !== "readonly").map((tab) => ({
    label: tab.label,
    href: tab.href,
    current: tab.key === current,
  }));
}

/**
 * Header for every Enrollment page: breadcrumb, title, actions, then the
 * stat row (if any) and the sub-tabs, in the shared page-template order.
 */
export function EnrollmentHeader({
  tab,
  role,
  title,
  description,
  actions,
  stats,
  trail = [],
  status,
}: {
  tab: EnrollmentTab;
  role: DashboardRole;
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  stats?: ReactNode;
  /** Extra crumbs after "Enrollment", e.g. the sub-page. */
  trail?: Crumb[];
  status?: ReactNode;
}) {
  const breadcrumb: Crumb[] = [
    { label: "Administration" },
    ...(tab === "overview" && trail.length === 0 ? [{ label: "Enrollment" }] : [{ label: "Enrollment", href: "/enrollment" }, ...trail]),
  ];
  return (
    <>
      <PageHeader breadcrumb={breadcrumb} title={title} status={status} description={description} actions={actions} />
      {stats}
      <TabNav label="Enrollment sections" tabs={enrollmentTabs(tab, role)} />
    </>
  );
}
