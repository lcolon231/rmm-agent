// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import { cookies } from "next/headers";

import {
  type DashboardSessionState,
  sessionCookieName,
} from "@/lib/dashboard-auth-core";
import { NodelinkApiError } from "@/lib/nodelink-api";
import { currentOperator } from "@/lib/nodelink-auth";

export async function getDashboardSession(): Promise<DashboardSessionState> {
  const cookieStore = await cookies();
  const sessionToken = cookieStore.get(sessionCookieName())?.value;
  if (!sessionToken) {
    return { kind: "anonymous" };
  }

  try {
    return {
      kind: "authenticated",
      operator: await currentOperator(sessionToken),
      sessionToken,
    };
  } catch (error) {
    if (error instanceof NodelinkApiError && (error.status === 401 || error.status === 403)) {
      return { kind: "anonymous" };
    }
    return { kind: "unavailable" };
  }
}
