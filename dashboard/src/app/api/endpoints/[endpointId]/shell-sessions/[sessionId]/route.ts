// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { closeShellSession, getShellSession } from "@/lib/shell-session";
import {
  handleCloseShellSession,
  handleGetShellSession,
} from "@/lib/shell-session-route-core";

export const dynamic = "force-dynamic";

type Context = { params: Promise<{ endpointId: string; sessionId: string }> };

export async function GET(request: NextRequest, { params }: Context) {
  const { endpointId, sessionId } = await params;
  return handleGetShellSession(request, endpointId, sessionId, {
    getSession: getDashboardSession,
    getShellSession,
  });
}

export async function POST(request: NextRequest, { params }: Context) {
  const { endpointId, sessionId } = await params;
  return handleCloseShellSession(request, endpointId, sessionId, {
    closeShellSession,
    getSession: getDashboardSession,
  });
}
