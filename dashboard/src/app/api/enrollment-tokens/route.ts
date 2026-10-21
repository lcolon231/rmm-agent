// SPDX-License-Identifier: AGPL-3.0-only

import { getDashboardSession } from "@/lib/dashboard-session";
import { createEnrollmentToken } from "@/lib/enrollment";
import { handleCreateEnrollmentToken } from "@/lib/enrollment-route-core";

export const dynamic = "force-dynamic";

export function POST(request: Request) {
  return handleCreateEnrollmentToken(request, {
    createEnrollmentToken,
    getSession: getDashboardSession,
  });
}
