// SPDX-License-Identifier: AGPL-3.0-only

import Link from "next/link";

export default function MonitoringPolicyNotFound() {
  return (
    <section className="enrollment-empty" role="alert">
      <h1>Monitoring policy not found</h1>
      <p>The policy may have been deleted or the link is no longer valid.</p>
      <Link href="/monitoring">Return to monitoring policies</Link>
    </section>
  );
}
