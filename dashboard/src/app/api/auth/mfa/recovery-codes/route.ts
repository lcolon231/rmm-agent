// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { handleGenerateRecoveryCodes } from "@/lib/mfa-route-core";
import { applyMfaResult } from "@/lib/mfa-route";
import { generateRecoveryCodes, readMfaCookie } from "@/lib/nodelink-mfa";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  return applyMfaResult(
    await handleGenerateRecoveryCodes(request, {
      generate: generateRecoveryCodes,
      getMfaToken: readMfaCookie,
      getSession: getDashboardSession,
    }),
  );
}
