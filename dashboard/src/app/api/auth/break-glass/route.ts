// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import {
  handleCreateBreakGlass,
  handleListBreakGlass,
} from "@/lib/admin-sessions-route-core";
import { applyAdminSessionResult } from "@/lib/admin-sessions-route";
import {
  createBreakGlassAccount,
  listBreakGlassAccounts,
} from "@/lib/nodelink-admin-sessions";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  return applyAdminSessionResult(
    await handleListBreakGlass(request, {
      getSession: getDashboardSession,
      list: listBreakGlassAccounts,
    }),
  );
}

export async function POST(request: NextRequest) {
  return applyAdminSessionResult(
    await handleCreateBreakGlass(request, {
      create: createBreakGlassAccount,
      getSession: getDashboardSession,
    }),
  );
}
