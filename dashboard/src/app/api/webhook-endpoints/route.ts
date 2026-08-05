// SPDX-License-Identifier: AGPL-3.0-only
import type { NextRequest } from "next/server";
import { getDashboardSession } from "@/lib/dashboard-session";
import { createWebhookEndpoint } from "@/lib/monitoring";
import { handleWebhookEndpointCreate } from "@/lib/webhook-route-core";

export function POST(request: NextRequest) {
  return handleWebhookEndpointCreate(request, {
    getSession: getDashboardSession,
    createEndpoint: createWebhookEndpoint,
  });
}
