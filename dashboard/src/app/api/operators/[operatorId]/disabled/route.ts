// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { changeManagedOperatorStatus } from "@/lib/operator-management";
import { handleChangeOperatorStatus } from "@/lib/operator-management-route-core";

export async function PUT(
  request: NextRequest,
  context: { params: Promise<{ operatorId: string }> },
) {
  const { operatorId } = await context.params;
  return handleChangeOperatorStatus(request, operatorId, {
    changeOperatorStatus: changeManagedOperatorStatus,
    getSession: getDashboardSession,
  });
}
