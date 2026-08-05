// SPDX-License-Identifier: AGPL-3.0-only
import type { NextRequest } from "next/server";
import { getDashboardSession } from "@/lib/dashboard-session";
import { addScriptVersion } from "@/lib/script-library";
import { handleScriptVersionCreate } from "@/lib/script-library-route-core";
export async function POST(request: NextRequest, context: { params: Promise<{ scriptId: string }> }) {
  const { scriptId } = await context.params;
  return handleScriptVersionCreate(request, scriptId, { getSession: getDashboardSession, addVersion: addScriptVersion });
}
