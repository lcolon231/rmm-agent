// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { readShellOutput } from "@/lib/shell-session";
import { handleShellOutput } from "@/lib/shell-session-route-core";

export const dynamic = "force-dynamic";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ endpointId: string; sessionId: string }> },
) {
  const { endpointId, sessionId } = await params;
  return handleShellOutput(request, endpointId, sessionId, {
    getSession: getDashboardSession,
    readShellOutput,
  });
}
