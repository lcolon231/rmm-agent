// SPDX-License-Identifier: AGPL-3.0-only

export type DashboardRole = "readonly" | "operator" | "admin";

export type DashboardOperator = {
  id: string;
  email: string;
  role: DashboardRole;
  disabled: boolean;
};

export type LoginCredentials = {
  email: string;
  password: string;
};

export type DashboardSessionState =
  | { kind: "anonymous" }
  | { kind: "authenticated"; operator: DashboardOperator }
  | { kind: "unavailable" };

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function validateLoginCredentials(value: unknown): LoginCredentials | null {
  if (!value || typeof value !== "object") {
    return null;
  }

  const { email, password } = value as Record<string, unknown>;
  if (typeof email !== "string" || typeof password !== "string") {
    return null;
  }

  const normalizedEmail = email.trim().toLowerCase();
  if (
    normalizedEmail.length === 0 ||
    normalizedEmail.length > 320 ||
    !emailPattern.test(normalizedEmail) ||
    password.length === 0 ||
    password.length > 1_024
  ) {
    return null;
  }

  return { email: normalizedEmail, password };
}

export function isSameOrigin(requestOrigin: string | null, expectedOrigin: string): boolean {
  return requestOrigin === expectedOrigin;
}

export function sessionCookieName(environment = process.env.NODE_ENV): string {
  return environment === "production" ? "__Host-nodelink-session" : "nodelink-session";
}

export function sessionCookieOptions(environment = process.env.NODE_ENV) {
  return {
    httpOnly: true,
    maxAge: 60 * 60,
    path: "/",
    priority: "high" as const,
    sameSite: "lax" as const,
    secure: environment === "production",
  };
}
