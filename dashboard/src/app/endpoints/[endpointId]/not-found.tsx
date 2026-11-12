// SPDX-License-Identifier: AGPL-3.0-only

import { Monitor } from "lucide-react";

import { ButtonLink } from "@/components/ui/button";
import { cardClass } from "@/components/ui/stat-tile";

export default function EndpointNotFound() {
  return (
    <section className={`${cardClass} flex flex-col items-center gap-2 px-6 py-10 text-center`}>
      <span className="flex size-12 items-center justify-center rounded-full bg-(--primary-tint) text-(--primary-strong)">
        <Monitor size={22} aria-hidden="true" />
      </span>
      <h1 className="m-0 mt-1 text-base font-semibold text-(--ink)">Device not found</h1>
      <p className="m-0 max-w-[420px] text-sm text-(--muted)">It may have been removed, or the link may no longer be valid.</p>
      <div className="mt-2">
        <ButtonLink href="/endpoints">Back to Endpoints</ButtonLink>
      </div>
    </section>
  );
}
