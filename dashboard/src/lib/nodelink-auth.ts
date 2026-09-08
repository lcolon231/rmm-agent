// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import type { DashboardOperator, LoginCredentials } from "@/lib/dashboard-auth-core";
import { nodelinkApiRequest } from "@/lib/nodelink-api";
import { getRuntimeConfig } from "@/lib/runtime-config";

type LoginResponse = {
  access_token: string | null;
  token_type: "bearer";
  mfa_required?: boolean;
};

export class NodelinkAuthenticationError extends Error {
  public readonly status: number;

  constructor(status: number) {
    super("NodeLink authentication failed.");
    this.name = "NodelinkAuthenticationError";
    this.status = status;
  }
}

/**
 * The password was accepted but a second factor is owed (issue #67).
 *
 * Signalled as a distinct throw rather than a nullable return so that no caller
 * can accidentally treat the half-authenticated state as a session: the only
 * way to reach the restricted token is to catch this deliberately.
 */
export class NodelinkSecondFactorRequired extends Error {
  public readonly body: unknown;

  constructor(body: unknown) {
    super("NodeLink requires a second authentication factor.");
    this.name = "NodelinkSecondFactorRequired";
    this.body = body;
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
  if (body.mfa_required === true) {
    throw new NodelinkSecondFactorRequired(body);
  }
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
