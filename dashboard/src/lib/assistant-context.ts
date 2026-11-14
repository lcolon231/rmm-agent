// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import { loadAssistantContext, type AssistantContext } from "@/lib/assistant-context-core";
import { getClientNavigation, type NavigationData } from "@/lib/client-navigation";
import { nodelinkApiRequest } from "@/lib/nodelink-api";

/**
 * Navigation and assistant status for a dashboard shell, fetched in parallel.
 * The status read uses the standard API timeout, not the long one assistant
 * runs need, so a slow assistant service cannot hold up a page render.
 */
export function getAssistantContext(sessionToken: string): Promise<AssistantContext<NavigationData>> {
  return loadAssistantContext({
    navigation: () => getClientNavigation(sessionToken),
    status: () => nodelinkApiRequest<unknown>("/api/v1/assistant/status", { method: "GET", sessionToken }),
  });
}
