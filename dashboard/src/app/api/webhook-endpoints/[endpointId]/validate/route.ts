// SPDX-License-Identifier: AGPL-3.0-only
import type { NextRequest } from "next/server";
import { getDashboardSession } from "@/lib/dashboard-session";
import { validateWebhookEndpoint } from "@/lib/monitoring";
import { handleWebhookEndpointValidate } from "@/lib/webhook-route-core";

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ endpointId: string }> },
) {
  const { endpointId } = await context.params;
  return handleWebhookEndpointValidate(request, endpointId, {
    getSession: getDashboardSession,
    validateEndpoint: validateWebhookEndpoint,
  });
}
