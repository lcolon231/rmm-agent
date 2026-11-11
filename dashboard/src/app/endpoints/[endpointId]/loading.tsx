// SPDX-License-Identifier: AGPL-3.0-only

import { Skeleton } from "@/components/ui/states";
import { cardClass } from "@/components/ui/stat-tile";

export default function EndpointLoading() {
  return (
    <div className="grid gap-6" aria-busy="true">
      <div className="grid gap-3">
        <span className="block h-3 w-48 rounded bg-[#ece9f5]" />
        <span className="block h-7 w-72 rounded bg-[#ece9f5]" />
        <span className="block h-4 w-96 max-w-full rounded bg-(--fog)" />
      </div>
      <div className={cardClass}>
        <Skeleton rows={6} label="Loading device details" />
      </div>
    </div>
  );
}
