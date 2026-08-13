// SPDX-License-Identifier: AGPL-3.0-only
import type { NextRequest } from "next/server";
import { getDashboardSession } from "@/lib/dashboard-session";
import {
  deleteMaintenanceWindow,
  getMaintenanceWindows,
} from "@/lib/maintenance-windows";
import { handleMaintenanceWindowDelete } from "@/lib/maintenance-window-route-core";

export const dynamic = "force-dynamic";

type Context = { params: Promise<{ windowId: string }> };

export async function DELETE(request: NextRequest, context: Context) {
  const { windowId } = await context.params;
  return handleMaintenanceWindowDelete(request, windowId, {
    getSession: getDashboardSession,
    listWindows: getMaintenanceWindows,
    deleteWindow: deleteMaintenanceWindow,
  });
}
