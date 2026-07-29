// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import type {
  ClientCreateInput,
  SiteCreateInput,
} from "@/lib/client-site-management-core";
import { nodelinkApiRequest } from "@/lib/nodelink-api";

export function createManagedClient(
  sessionToken: string,
  input: ClientCreateInput,
): Promise<unknown> {
  return nodelinkApiRequest<unknown>("/api/v1/clients", {
    body: JSON.stringify(input),
    headers: { "Content-Type": "application/json" },
    method: "POST",
    sessionToken,
  });
}

export function createManagedSite(
  sessionToken: string,
  input: SiteCreateInput,
): Promise<unknown> {
  return nodelinkApiRequest<unknown>("/api/v1/sites", {
    body: JSON.stringify(input),
    headers: { "Content-Type": "application/json" },
    method: "POST",
    sessionToken,
  });
}
