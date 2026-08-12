// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import type { SigningKeyInfo } from "@/lib/dashboard-overview-core";
import { nodelinkApiRequest } from "@/lib/nodelink-api";

export async function getSigningKeys(sessionToken: string): Promise<SigningKeyInfo> {
  return nodelinkApiRequest<SigningKeyInfo>("/api/v1/signing-keys", {
    method: "GET",
    sessionToken,
  });
}
