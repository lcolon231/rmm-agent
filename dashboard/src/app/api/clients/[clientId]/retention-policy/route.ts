// SPDX-License-Identifier: AGPL-3.0-only
import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { sendRetentionPolicy } from "@/lib/retention-policy";
import { handleRetentionPolicyRequest } from "@/lib/retention-policy-route-core";

export const dynamic = "force-dynamic";

type Context = { params: Promise<{ clientId: string }> };

async function handle(request: NextRequest, context: Context) {
  const { clientId } = await context.params;
  return handleRetentionPolicyRequest(request, clientId, {
    getSession: getDashboardSession,
    send: sendRetentionPolicy,
  });
}

export const GET = handle;
export const PUT = handle;
export const DELETE = handle;
