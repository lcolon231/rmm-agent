 export type RuntimeConfig = {
  apiBaseUrl: string;
  apiTimeoutMs: number;
};

type Environment = Record<string, string | undefined>;

const DEFAULT_DEVELOPMENT_API_URL = "http://127.0.0.1:8000";
const DEFAULT_TIMEOUT_MS = 10_000;
const MIN_TIMEOUT_MS = 1_000;
const MAX_TIMEOUT_MS = 60_000;

function isLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
}

function parseTimeout(value: string | undefined): number {
  if (value === undefined || value === "") {
    return DEFAULT_TIMEOUT_MS;
  }

  const timeoutMs = Number(value);
  if (
    !Number.isInteger(timeoutMs) ||
    timeoutMs < MIN_TIMEOUT_MS ||
    timeoutMs > MAX_TIMEOUT_MS
  ) {
    throw new Error(
      `NODELINK_API_TIMEOUT_MS must be an integer from ${MIN_TIMEOUT_MS} to ${MAX_TIMEOUT_MS}.`,
    );
  }

  return timeoutMs;
}

export function getRuntimeConfig(environment: Environment = process.env): RuntimeConfig {
  const isProduction = environment.NODE_ENV === "production";
  const rawApiBaseUrl = environment.NODELINK_API_BASE_URL ?? (
    isProduction ? undefined : DEFAULT_DEVELOPMENT_API_URL
  );

  if (!rawApiBaseUrl) {
    throw new Error("NODELINK_API_BASE_URL must be set in production.");
  }

  let apiUrl: URL;
  try {
    apiUrl = new URL(rawApiBaseUrl);
  } catch {
    throw new Error("NODELINK_API_BASE_URL must be an absolute HTTP(S) URL.");
  }

  if (apiUrl.protocol !== "http:" && apiUrl.protocol !== "https:") {
    throw new Error("NODELINK_API_BASE_URL must use HTTP or HTTPS.");
  }

  if (apiUrl.username || apiUrl.password) {
    throw new Error("NODELINK_API_BASE_URL must not include credentials.");
  }

  if (apiUrl.pathname !== "/" || apiUrl.search || apiUrl.hash) {
    throw new Error("NODELINK_API_BASE_URL must be an origin without a path, query, or fragment.");
  }

  if (apiUrl.protocol === "http:" && !isLoopbackHost(apiUrl.hostname)) {
    throw new Error("HTTP is allowed only for a loopback NodeLink API URL.");
  }

  return {
    apiBaseUrl: apiUrl.origin,
    apiTimeoutMs: parseTimeout(environment.NODELINK_API_TIMEOUT_MS),
  };
}
