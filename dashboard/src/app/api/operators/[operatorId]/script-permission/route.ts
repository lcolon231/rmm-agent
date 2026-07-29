// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { handleGrantScriptPermission } from "@/lib/operator-management-route-core";
import { grantScriptPermission } from "@/lib/operator-management";

export async function PUT(
  request: NextRequest,
  context: { params: Promise<{ operatorId: string }> },
) {
  const { operatorId } = await context.params;
  return handleGrantScriptPermission(request, operatorId, {
    getSession: getDashboardSession,
    grantScriptPermission,
  });
}
