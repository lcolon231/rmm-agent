// SPDX-License-Identifier: AGPL-3.0-only

import { handleLogout } from "@/lib/auth-route-core";
import { getDashboardSession } from "@/lib/dashboard-session";
import { applyMfaResult } from "@/lib/mfa-route";
import { revokeOperatorTokens } from "@/lib/nodelink-auth";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  return applyMfaResult(await handleLogout(request, {
    getSession: getDashboardSession,
    revokeOperatorTokens,
  }));
}
