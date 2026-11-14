// SPDX-License-Identifier: AGPL-3.0-only

import type { NavigationData } from "@/lib/client-navigation";
import type { DashboardOperator } from "@/lib/dashboard-auth-core";

import { AppShell } from "./shell/app-shell";

/** The app shell for a section layout (everything except Overview, which passes scope). */
export function DashboardSectionShell({
  activePath,
  assistantState,
  children,
  navigation,
  navigationError,
  operator,
}: {
  activePath: string;
  /** Assistant pilot state; omit to leave the floating assistant off this shell. */
  assistantState?: string;
  children: React.ReactNode;
  navigation: NavigationData | null;
  navigationError: boolean;
  operator: DashboardOperator;
}) {
  return (
    <AppShell activePath={activePath} navigation={navigation} navigationError={navigationError} operator={operator} assistantState={assistantState}>
      {children}
    </AppShell>
  );
}
