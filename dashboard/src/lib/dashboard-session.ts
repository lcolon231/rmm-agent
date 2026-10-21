// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import { cookies } from "next/headers";

import {
  type DashboardSessionState,
  sessionCookieName,
} from "@/lib/dashboard-auth-core";
import { resolveDashboardSession } from "@/lib/dashboard-session-core";
import { currentOperator } from "@/lib/nodelink-auth";

export async function getDashboardSession(): Promise<DashboardSessionState> {
  const cookieStore = await cookies();
  return resolveDashboardSession(cookieStore.get(sessionCookieName())?.value, currentOperator);
}
