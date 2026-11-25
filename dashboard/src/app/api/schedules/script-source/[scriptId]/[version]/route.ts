// SPDX-License-Identifier: AGPL-3.0-only

import { getDashboardSession } from "@/lib/dashboard-session";
import { getScriptVersion } from "@/lib/script-library";
import { handleScheduleScriptSource } from "@/lib/schedules-route-core";

export const dynamic = "force-dynamic";

export async function GET(request: Request, context: { params: Promise<{ scriptId: string; version: string }> }) {
  const { scriptId, version } = await context.params;
  return handleScheduleScriptSource(request, scriptId, version, {
    getScriptVersion,
    getSession: getDashboardSession,
  });
}
