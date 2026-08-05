// SPDX-License-Identifier: AGPL-3.0-only
import type { NextRequest } from "next/server";
import { getDashboardSession } from "@/lib/dashboard-session";
import { deleteWebhookEndpoint, updateWebhookEndpoint } from "@/lib/monitoring";
import {
  handleWebhookEndpointDelete,
  handleWebhookEndpointUpdate,
} from "@/lib/webhook-route-core";

type Context = { params: Promise<{ endpointId: string }> };

export async function PUT(request: NextRequest, context: Context) {
  const { endpointId } = await context.params;
  return handleWebhookEndpointUpdate(request, endpointId, {
    getSession: getDashboardSession,
    updateEndpoint: updateWebhookEndpoint,
  });
}

export async function DELETE(request: NextRequest, context: Context) {
  const { endpointId } = await context.params;
  return handleWebhookEndpointDelete(request, endpointId, {
    getSession: getDashboardSession,
    deleteEndpoint: deleteWebhookEndpoint,
  });
}
