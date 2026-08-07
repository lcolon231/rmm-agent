// SPDX-License-Identifier: AGPL-3.0-only
import type { NextRequest } from "next/server";
import { getDashboardSession } from "@/lib/dashboard-session";
import { prepareScriptParameterValues } from "@/lib/script-library";
import { handleScriptParameterValues } from "@/lib/script-library-route-core";

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ scriptId: string; version: string }> },
) {
  const { scriptId, version } = await context.params;
  return handleScriptParameterValues(request, scriptId, Number(version), {
    getSession: getDashboardSession,
    prepare: prepareScriptParameterValues,
  });
}
