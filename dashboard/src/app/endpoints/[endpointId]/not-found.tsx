// SPDX-License-Identifier: AGPL-3.0-only

import Link from "next/link";

export default function EndpointNotFound() {
  return (
    <main className="detail-failure-page">
      <section><span>Endpoint lookup</span><h1>Endpoint not found</h1><p>This endpoint may have been removed, or the link may no longer be valid.</p><Link href="/">Return to fleet</Link></section>
    </main>
  );
}
