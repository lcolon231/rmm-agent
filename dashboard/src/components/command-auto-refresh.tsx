// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

/** Re-fetches server data on an interval while commands are still in flight,
 * so status and results appear without manual reloading. */
export function CommandAutoRefresh({ intervalMs = 5_000 }: { intervalMs?: number }) {
  const router = useRouter();

  useEffect(() => {
    const timer = setInterval(() => router.refresh(), intervalMs);
    return () => clearInterval(timer);
  }, [router, intervalMs]);

  return null;
}
