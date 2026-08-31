// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { handleRenameCredential } from "@/lib/mfa-route-core";
import { applyMfaResult } from "@/lib/mfa-route";
import { readMfaCookie, renameCredential } from "@/lib/nodelink-mfa";

export const dynamic = "force-dynamic";

export async function PUT(
  request: NextRequest,
  context: { params: Promise<{ credentialId: string }> },
) {
  const { credentialId } = await context.params;
  return applyMfaResult(
    await handleRenameCredential(request, credentialId, {
      getMfaToken: readMfaCookie,
      getSession: getDashboardSession,
      rename: renameCredential,
    }),
  );
}
