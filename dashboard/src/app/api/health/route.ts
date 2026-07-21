import { getNodelinkHealth } from "@/lib/nodelink-health-core";
import { getRuntimeConfig } from "@/lib/runtime-config";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const health = await getNodelinkHealth({
      fetchImpl: fetch,
      runtimeConfig: getRuntimeConfig(),
    });

    if (health === "ok") {
      return Response.json({ status: "ok" });
    }
  } catch {
    // Configuration and upstream failures intentionally share the same response.
  }

  return Response.json({ status: "degraded" }, { status: 503 });
}
