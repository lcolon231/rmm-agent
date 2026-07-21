import type { RuntimeConfig } from "@/lib/runtime-config";

type HealthDependencies = {
  fetchImpl: typeof fetch;
  runtimeConfig: RuntimeConfig;
};

export async function getNodelinkHealth({
  fetchImpl,
  runtimeConfig,
}: HealthDependencies): Promise<"ok" | "degraded"> {
  try {
    const response = await fetchImpl(new URL("/healthz", runtimeConfig.apiBaseUrl), {
      cache: "no-store",
      signal: AbortSignal.timeout(runtimeConfig.apiTimeoutMs),
    });
    return response.ok ? "ok" : "degraded";
  } catch {
    return "degraded";
  }
}
