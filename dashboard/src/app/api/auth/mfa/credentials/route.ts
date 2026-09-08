// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { handleRegisterCredential } from "@/lib/mfa-route-core";
import { applyMfaResult } from "@/lib/mfa-route";
import { readMfaCookie, registerCredential } from "@/lib/nodelink-mfa";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  return applyMfaResult(
    await handleRegisterCredential(request, {
      getMfaToken: readMfaCookie,
      getSession: getDashboardSession,
      register: registerCredential,
    }),
  );
}
