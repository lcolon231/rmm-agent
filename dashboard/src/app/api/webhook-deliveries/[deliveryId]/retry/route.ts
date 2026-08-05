// SPDX-License-Identifier: AGPL-3.0-only
import type { NextRequest } from "next/server";
import { getDashboardSession } from "@/lib/dashboard-session";
import { retryAlertWebhookDelivery } from "@/lib/monitoring";
import { handleWebhookDeliveryRetry } from "@/lib/webhook-route-core";

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ deliveryId: string }> },
) {
  const { deliveryId } = await context.params;
  return handleWebhookDeliveryRetry(request, deliveryId, {
    getSession: getDashboardSession,
    retryDelivery: retryAlertWebhookDelivery,
  });
}
