// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { createManagedSite } from "@/lib/client-site-management";
import { handleCreateSite } from "@/lib/client-site-management-route-core";
import { getDashboardSession } from "@/lib/dashboard-session";

export function POST(request: NextRequest) {
  return handleCreateSite(request, {
    createSite: createManagedSite,
    getSession: getDashboardSession,
  });
}
