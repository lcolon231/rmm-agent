// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { startSupportConversation } from "@/lib/support";
import { handleStartConversation } from "@/lib/support-route-core";

export const dynamic = "force-dynamic";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ endpointId: string }> },
) {
  const { endpointId } = await params;
  return handleStartConversation(request, endpointId, {
    getSession: getDashboardSession,
    startSupportConversation,
  });
}
