// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { createManagedClient } from "@/lib/client-site-management";
import { handleCreateClient } from "@/lib/client-site-management-route-core";
import { getDashboardSession } from "@/lib/dashboard-session";

export function POST(request: NextRequest) {
  return handleCreateClient(request, {
    createClient: createManagedClient,
    getSession: getDashboardSession,
  });
}
