// SPDX-License-Identifier: AGPL-3.0-only
import type { NextRequest } from "next/server";
import { communityMutation } from "@/lib/community-packages";
import { handleCommunityAction, resolveCommunityRoute } from "@/lib/community-packages-route-core";
import { getDashboardSession } from "@/lib/dashboard-session";

export async function POST(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const route = resolveCommunityRoute((await context.params).path);
  if (!route) return Response.json({ error: "Unknown repository action." }, { status: 404 });
  return handleCommunityAction(request, route.action, route.params, {
    getSession: getDashboardSession, mutate: communityMutation,
  });
}
