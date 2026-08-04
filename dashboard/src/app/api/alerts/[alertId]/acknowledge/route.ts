// SPDX-License-Identifier: AGPL-3.0-only
import type { NextRequest } from "next/server";
import { handleAlertAction } from "@/lib/alert-action-route-core";
import { getDashboardSession } from "@/lib/dashboard-session";
import { performAlertAction } from "@/lib/monitoring";

export async function POST(request: NextRequest, context: { params: Promise<{ alertId: string }> }) {
  const { alertId } = await context.params;
  return handleAlertAction(request, alertId, "acknowledge", {
    getSession: getDashboardSession, performAction: performAlertAction,
  });
}
