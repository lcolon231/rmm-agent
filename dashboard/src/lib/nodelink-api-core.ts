import type { RuntimeConfig } from "@/lib/runtime-config";

export type NodelinkRequestOptions = Omit<RequestInit, "headers" | "signal"> & {
  headers?: HeadersInit;
  sessionToken: string;
  signal?: AbortSignal;
};

type RequestDependencies = {
  fetchImpl: typeof fetch;
  runtimeConfig: RuntimeConfig;
};

export class NodelinkApiError extends Error {
  public readonly status: number;

  constructor(status: number, message = "NodeLink API request failed.") {
    super(message);
    this.name = "NodelinkApiError";
    this.status = status;
  }
}

export async function requestNodelinkApi<T>(
  path: string,
  { headers, sessionToken, signal, ...options }: NodelinkRequestOptions,
  { fetchImpl, runtimeConfig }: RequestDependencies,
): Promise<T> {
  if (!path.startsWith("/")) {
    throw new Error("NodeLink API paths must start with '/'.");
  }

  if (!sessionToken.trim()) {
    throw new Error("A server-managed operator session is required for NodeLink API access.");
  }

  const requestHeaders = new Headers(headers);
  requestHeaders.set("Authorization", `Bearer ${sessionToken}`);
  requestHeaders.set("Accept", "application/json");

  const response = await fetchImpl(new URL(path, runtimeConfig.apiBaseUrl), {
    ...options,
    cache: "no-store",
    headers: requestHeaders,
    signal: signal ?? AbortSignal.timeout(runtimeConfig.apiTimeoutMs),
  });

  if (!response.ok) {
    throw new NodelinkApiError(response.status);
  }

  return response.json() as Promise<T>;
}
