// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { cardClass } from "@/components/ui/stat-tile";
import { ErrorState } from "@/components/ui/states";

export default function EnrollmentError({ reset }: { error: Error; reset: () => void }) {
  return (
    <section className={cardClass}>
      <ErrorState
        title="Enrollment data is unavailable"
        body="The management service did not return a usable response"
        onRetry={reset}
      />
    </section>
  );
}
