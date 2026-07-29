// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { changeManagedOperatorRole } from "@/lib/operator-management";
import { handleChangeOperatorRole } from "@/lib/operator-management-route-core";

export async function PUT(
  request: NextRequest,
  context: { params: Promise<{ operatorId: string }> },
) {
  const { operatorId } = await context.params;
  return handleChangeOperatorRole(request, operatorId, {
    changeOperatorRole: changeManagedOperatorRole,
    getSession: getDashboardSession,
  });
}
