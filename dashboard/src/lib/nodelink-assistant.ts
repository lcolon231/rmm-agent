// SPDX-License-Identifier: AGPL-3.0-only
import "server-only";
import { nodelinkApiRequest } from "@/lib/nodelink-api";

export function assistantRequest(path: string, sessionToken: string, method = "GET", body?: string): Promise<unknown> {
  return nodelinkApiRequest(path, { sessionToken, method, body,
    headers: { "Content-Type": "application/json" }, signal: AbortSignal.timeout(55000) });
}
