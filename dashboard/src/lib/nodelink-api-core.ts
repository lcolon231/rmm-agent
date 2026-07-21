// SPDX-License-Identifier: AGPL-3.0-only

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
  /** Stable machine code from the API's error detail, when it sent one. */
  public readonly code: string | null;

  constructor(status: number, message = "NodeLink API request failed.", code: string | null = null) {
    super(message);
    this.name = "NodelinkApiError";
    this.status = status;
    this.code = code;
  }
}

export function extractNodelinkErrorCode(body: unknown): string | null {
  if (!body || typeof body !== "object") return null;
  const detail = (body as Record<string, unknown>).detail;
  if (!detail || typeof detail !== "object") return null;
  const code = (detail as Record<string, unknown>).code;
  return typeof code === "string" ? code : null;
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
    const errorBody = await response.json().catch(() => null);
    throw new NodelinkApiError(
      response.status,
      undefined,
      extractNodelinkErrorCode(errorBody),
    );
  }

  return response.json() as Promise<T>;
}
