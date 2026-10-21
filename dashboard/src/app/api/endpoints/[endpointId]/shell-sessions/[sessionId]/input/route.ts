// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { sendShellInput } from "@/lib/shell-session";
import { handleShellInput } from "@/lib/shell-session-route-core";

export const dynamic = "force-dynamic";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ endpointId: string; sessionId: string }> },
) {
  const { endpointId, sessionId } = await params;
  return handleShellInput(request, endpointId, sessionId, {
    getSession: getDashboardSession,
    sendShellInput,
  });
}
