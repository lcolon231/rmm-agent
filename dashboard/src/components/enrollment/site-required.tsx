// SPDX-License-Identifier: AGPL-3.0-only

import { MapPin, Plus } from "lucide-react";

import { ButtonLink } from "@/components/ui/button";
import { cardClass } from "@/components/ui/stat-tile";

/** Shown instead of a form that needs a site when none exists yet. */
export function SiteRequired({ body }: { body: string }) {
  return (
    <section className={`${cardClass} flex max-w-[640px] flex-col items-center gap-2 px-6 py-10 text-center`}>
      <span className="flex size-12 items-center justify-center rounded-full bg-(--primary-tint) text-(--primary-strong)">
        <MapPin size={22} aria-hidden="true" />
      </span>
      <h2 className="m-0 mt-1 text-base font-semibold text-(--ink)">A site is needed first</h2>
      <p className="m-0 max-w-[420px] text-sm text-(--muted)">{body}</p>
      <div className="mt-2">
        <ButtonLink href="/enrollment/setup" variant="primary" icon={Plus}>
          Create client and site
        </ButtonLink>
      </div>
    </section>
  );
}
