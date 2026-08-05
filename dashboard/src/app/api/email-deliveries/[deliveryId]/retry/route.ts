// SPDX-License-Identifier: AGPL-3.0-only
import type { NextRequest } from "next/server";
import { getDashboardSession } from "@/lib/dashboard-session";
import { handleEmailDeliveryRetry } from "@/lib/email-delivery-route-core";
import { retryAlertEmailDelivery } from "@/lib/monitoring";

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ deliveryId: string }> },
) {
  const { deliveryId } = await context.params;
  return handleEmailDeliveryRetry(request, deliveryId, {
    getSession: getDashboardSession,
    retryDelivery: retryAlertEmailDelivery,
  });
}
