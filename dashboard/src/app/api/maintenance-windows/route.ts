// SPDX-License-Identifier: AGPL-3.0-only
import type { NextRequest } from "next/server";
import { getDashboardSession } from "@/lib/dashboard-session";
import { createMaintenanceWindow } from "@/lib/maintenance-windows";
import { handleMaintenanceWindowCreate } from "@/lib/maintenance-window-route-core";

export const dynamic = "force-dynamic";

export function POST(request: NextRequest) {
  return handleMaintenanceWindowCreate(request, {
    getSession: getDashboardSession,
    createWindow: createMaintenanceWindow,
  });
}
