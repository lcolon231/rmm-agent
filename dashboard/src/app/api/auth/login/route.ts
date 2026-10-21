// SPDX-License-Identifier: AGPL-3.0-only

import { handleLogin } from "@/lib/auth-route-core";
import { applyMfaResult } from "@/lib/mfa-route";
import { attemptOperatorLogin } from "@/lib/nodelink-auth";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  return applyMfaResult(await handleLogin(request, { authenticate: attemptOperatorLogin }));
}
