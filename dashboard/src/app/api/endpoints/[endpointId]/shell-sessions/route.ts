// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { openShellSession } from "@/lib/shell-session";
import { handleOpenShellSession } from "@/lib/shell-session-route-core";

export const dynamic = "force-dynamic";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ endpointId: string }> },
) {
  const { endpointId } = await params;
  return handleOpenShellSession(request, endpointId, {
    getSession: getDashboardSession,
    openShellSession,
  });
}
