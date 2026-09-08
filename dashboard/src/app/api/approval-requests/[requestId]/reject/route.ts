// SPDX-License-Identifier: AGPL-3.0-only
import type { NextRequest } from "next/server";
import { handleApprovalAction } from "@/lib/approval-route-core";
import { performApprovalAction } from "@/lib/approvals";
import { getDashboardSession } from "@/lib/dashboard-session";

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ requestId: string }> },
) {
  const { requestId } = await context.params;
  return handleApprovalAction(request, requestId, "reject", {
    getSession: getDashboardSession,
    performAction: performApprovalAction,
  });
}
