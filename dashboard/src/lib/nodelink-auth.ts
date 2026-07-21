import "server-only";

import type { DashboardOperator, LoginCredentials } from "@/lib/dashboard-auth-core";
import { nodelinkApiRequest } from "@/lib/nodelink-api";
import { getRuntimeConfig } from "@/lib/runtime-config";

type LoginResponse = {
  access_token: string;
  token_type: "bearer";
};

export class NodelinkAuthenticationError extends Error {
  public readonly status: number;

  constructor(status: number) {
    super("NodeLink authentication failed.");
    this.name = "NodelinkAuthenticationError";
    this.status = status;
  }
}

export async function authenticateOperator(credentials: LoginCredentials) {
  const { apiBaseUrl, apiTimeoutMs } = getRuntimeConfig();
  const response = await fetch(new URL("/api/v1/auth/login", apiBaseUrl), {
    body: JSON.stringify(credentials),
    cache: "no-store",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    method: "POST",
    signal: AbortSignal.timeout(apiTimeoutMs),
  });

  if (!response.ok) {
    throw new NodelinkAuthenticationError(response.status);
  }

  const body = await response.json() as LoginResponse;
  if (body.token_type !== "bearer" || !body.access_token) {
    throw new NodelinkAuthenticationError(502);
  }

  const operator = await currentOperator(body.access_token);
  return { operator, sessionToken: body.access_token };
}

export async function currentOperator(sessionToken: string): Promise<DashboardOperator> {
  return nodelinkApiRequest<DashboardOperator>("/api/v1/auth/me", {
    method: "GET",
    sessionToken,
  });
}

export async function revokeOperatorTokens(sessionToken: string): Promise<void> {
  await nodelinkApiRequest<void>("/api/v1/auth/revoke-tokens", {
    method: "POST",
    sessionToken,
  });
}
