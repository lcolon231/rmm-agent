// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import { nodelinkApiRequest } from "@/lib/nodelink-api";

export type NavigationSite = {
  id: string;
  client_id: string;
  name: string;
  endpoint_count: number;
};

export type NavigationClient = {
  id: string;
  name: string;
  sites: NavigationSite[];
};

export type NavigationData = {
  items: NavigationClient[];
  truncated: boolean;
};

export async function getClientNavigation(sessionToken: string): Promise<NavigationData> {
  return nodelinkApiRequest<NavigationData>("/api/v1/clients/navigation", {
    method: "GET",
    sessionToken,
  });
}
