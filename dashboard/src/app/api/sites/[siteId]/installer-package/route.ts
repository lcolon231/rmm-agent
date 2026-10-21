// SPDX-License-Identifier: AGPL-3.0-only

import { getDashboardSession } from "@/lib/dashboard-session";
import { requestInstallerPackage } from "@/lib/enrollment";
import { handleInstallerPackage } from "@/lib/enrollment-route-core";

export const dynamic = "force-dynamic";

export async function POST(request: Request, context: { params: Promise<{ siteId: string }> }) {
  const { siteId } = await context.params;
  return handleInstallerPackage(request, siteId, {
    getSession: getDashboardSession,
    requestInstallerPackage,
  });
}
