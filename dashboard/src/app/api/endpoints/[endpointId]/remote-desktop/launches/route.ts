// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { launchRemoteDesktop } from "@/lib/remote-desktop";
import { handleLaunchRemoteDesktop } from "@/lib/remote-desktop-route-core";

export const dynamic = "force-dynamic";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ endpointId: string }> },
) {
  const { endpointId } = await params;
  return handleLaunchRemoteDesktop(request, endpointId, {
    getSession: getDashboardSession,
    launchRemoteDesktop,
  });
}
