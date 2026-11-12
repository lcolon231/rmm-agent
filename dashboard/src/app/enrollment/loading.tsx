// SPDX-License-Identifier: AGPL-3.0-only

import { cardClass } from "@/components/ui/stat-tile";
import { Skeleton } from "@/components/ui/states";

export default function LoadingEnrollment() {
  return (
    <section className={cardClass}>
      <Skeleton rows={5} label="Loading enrollment" />
    </section>
  );
}
