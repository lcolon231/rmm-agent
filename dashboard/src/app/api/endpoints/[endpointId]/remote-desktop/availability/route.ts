// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { getRemoteDesktopAvailability } from "@/lib/remote-desktop";
import { handleRemoteDesktopAvailability } from "@/lib/remote-desktop-route-core";

export const dynamic = "force-dynamic";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ endpointId: string }> },
) {
  const { endpointId } = await params;
  return handleRemoteDesktopAvailability(request, endpointId, {
    getRemoteDesktopAvailability,
    getSession: getDashboardSession,
  });
}
