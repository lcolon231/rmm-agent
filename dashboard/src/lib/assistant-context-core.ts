// SPDX-License-Identifier: AGPL-3.0-only

/** What a dashboard shell needs to mount the assistant: the client list and the pilot state. */
export type AssistantContext<Navigation> = { clients: Navigation | null; state: string };

/**
 * Loads navigation and assistant status together. Either may fail on its own:
 * no client list is `null`, and any status failure reads as "unavailable".
 */
export async function loadAssistantContext<Navigation>(deps: {
  navigation: () => Promise<Navigation>;
  status: () => Promise<unknown>;
}): Promise<AssistantContext<Navigation>> {
  const [navigation, status] = await Promise.allSettled([deps.navigation(), deps.status()]);
  return {
    clients: navigation.status === "fulfilled" ? navigation.value : null,
    state:
      status.status === "fulfilled" && status.value && typeof status.value === "object" && "state" in status.value
        ? String(status.value.state)
        : "unavailable",
  };
}

const ENDPOINT_ID = /^[a-f0-9-]{36}$/i;
const ENDPOINT_ROUTE = /^\/endpoints\/([^/]+)/;

export type AssistantPrefill = { clientId?: string; endpointId?: string };

/**
 * The client and endpoint an assistant conversation starts from. `client_id`
 * must be a client the operator can see; the endpoint comes from `endpoint_id`
 * or, on `/endpoints/<id>`, from the route segment.
 */
export function assistantPrefill(
  pathname: string,
  params: { client_id?: string | null; endpoint_id?: string | null },
  clientIds: readonly string[],
): AssistantPrefill {
  const clientId = params.client_id && clientIds.includes(params.client_id) ? params.client_id : undefined;
  const candidate = params.endpoint_id ?? ENDPOINT_ROUTE.exec(pathname)?.[1];
  const endpointId = typeof candidate === "string" && ENDPOINT_ID.test(candidate) ? candidate : undefined;
  return { clientId, endpointId };
}

/** The full-page assistant, carrying the same client and endpoint. */
export function assistantPageHref({ clientId, endpointId }: AssistantPrefill): string {
  const query = new URLSearchParams();
  if (clientId) query.set("client_id", clientId);
  if (endpointId) query.set("endpoint_id", endpointId);
  const text = query.toString();
  return text ? `/assistant?${text}` : "/assistant";
}
