// SPDX-License-Identifier: AGPL-3.0-only

import { handleMfaStatus } from "@/lib/auth-route-core";
import { getDashboardSession } from "@/lib/dashboard-session";
import { fetchMfaStatus } from "@/lib/nodelink-mfa";

export const dynamic = "force-dynamic";

export function GET(request: Request) {
  return handleMfaStatus(request, { fetchMfaStatus, getSession: getDashboardSession });
}
