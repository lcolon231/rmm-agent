// SPDX-License-Identifier: AGPL-3.0-only

import Link from "next/link";

export default function AuditEventNotFound() {
  return (
    <section className="enrollment-empty">
      <h1>Audit event not found</h1>
      <p>
        No event with this identifier exists in the chain. A link may be stale, or the identifier may
        belong to a different deployment.
      </p>
      <Link href="/audit">Back to the timeline</Link>
    </section>
  );
}
