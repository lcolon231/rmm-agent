// SPDX-License-Identifier: AGPL-3.0-only

import type { NextRequest } from "next/server";

import { getDashboardSession } from "@/lib/dashboard-session";
import { handleLoginOptions } from "@/lib/mfa-route-core";
import { applyMfaResult } from "@/lib/mfa-route";
import { fetchLoginOptions, readMfaCookie } from "@/lib/nodelink-mfa";

export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  return applyMfaResult(
    await handleLoginOptions(request, {
      fetchOptions: fetchLoginOptions,
      getMfaToken: readMfaCookie,
      getSession: getDashboardSession,
    }),
  );
}
