// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { dispatchCommand } from "@/lib/command-console";
import { handleDispatchCommand } from "@/lib/command-dispatch-route-core";
import { getDashboardSession } from "@/lib/dashboard-session";

export const dynamic = "force-dynamic";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ endpointId: string }> },
) {
  const { endpointId } = await params;
  return handleDispatchCommand(request, endpointId, {
    dispatchCommand,
    getSession: getDashboardSession,
  });
}
