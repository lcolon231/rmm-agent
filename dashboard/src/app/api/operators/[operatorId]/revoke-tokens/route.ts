// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { handleRevokeOperatorTokens } from "@/lib/operator-management-route-core";
import { revokeManagedOperatorTokens } from "@/lib/operator-management";

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ operatorId: string }> },
) {
  const { operatorId } = await context.params;
  return handleRevokeOperatorTokens(request, operatorId, {
    getSession: getDashboardSession,
    revokeOperatorTokens: revokeManagedOperatorTokens,
  });
}
