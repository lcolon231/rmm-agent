// SPDX-License-Identifier: AGPL-3.0-only

import { handleHealth } from "@/lib/auth-route-core";
import { getNodelinkHealth } from "@/lib/nodelink-health-core";
import { getRuntimeConfig } from "@/lib/runtime-config";

export const dynamic = "force-dynamic";

export function GET() {
  return handleHealth({
    checkHealth: () => getNodelinkHealth({ fetchImpl: fetch, runtimeConfig: getRuntimeConfig() }),
  });
}
