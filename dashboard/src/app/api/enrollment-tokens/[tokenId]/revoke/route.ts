// SPDX-License-Identifier: AGPL-3.0-only

import { getDashboardSession } from "@/lib/dashboard-session";
import { revokeEnrollmentToken } from "@/lib/enrollment";
import { handleRevokeEnrollmentToken } from "@/lib/enrollment-route-core";

export const dynamic = "force-dynamic";

export async function POST(request: Request, context: { params: Promise<{ tokenId: string }> }) {
  const { tokenId } = await context.params;
  return handleRevokeEnrollmentToken(request, tokenId, {
    getSession: getDashboardSession,
    revokeEnrollmentToken,
  });
}
