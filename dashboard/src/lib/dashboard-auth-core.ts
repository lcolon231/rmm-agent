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

export type LoginSubmission = {
  body: unknown;
  kind: "form" | "json";
};

export type LoginErrorCode =
  | "invalid-request"
  | "invalid-credentials"
  | "rate-limited"
  | "request-rejected"
  | "unavailable";

export type DashboardSessionState =
  | { kind: "anonymous" }
  | { kind: "authenticated"; operator: DashboardOperator; sessionToken: string }
  | { kind: "unavailable" };

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const loginErrorMessages: Record<LoginErrorCode, string> = {
  "invalid-request": "Enter a valid email and password.",
  "invalid-credentials": "Email or password is incorrect.",
  "rate-limited": "Too many sign-in attempts. Try again later.",
  "request-rejected": "Sign-in request was rejected.",
  unavailable: "Sign-in is unavailable. Try again later.",
};

export async function readLoginSubmission(request: Request): Promise<LoginSubmission | null> {
  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";

  try {
    if (contentType.startsWith("application/json")) {
      return { body: await request.json(), kind: "json" };
    }

    if (
      contentType.startsWith("application/x-www-form-urlencoded")
      || contentType.startsWith("multipart/form-data")
    ) {
      const formData = await request.formData();
      return {
        body: {
          email: formData.get("email"),
          password: formData.get("password"),
        },
        kind: "form",
      };
    }
  } catch {
    return null;
  }

  return null;
}

export function loginErrorMessage(value: unknown): string | undefined {
  if (typeof value !== "string" || !(value in loginErrorMessages)) {
    return undefined;
  }

  return loginErrorMessages[value as LoginErrorCode];
}

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

export function requestOrigin(requestUrl: string, host: string | null): string {
  const url = new URL(requestUrl);
  if (!host || host.includes("/") || host.includes("@") || /\s/.test(host)) {
    return url.origin;
  }

  url.host = host;
  return url.origin;
}

export function sanitizedLoginUrl(url: URL): URL | null {
  if (!url.searchParams.has("email") && !url.searchParams.has("password")) {
    return null;
  }

  const sanitized = new URL(url);
  sanitized.search = "";
  return sanitized;
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
