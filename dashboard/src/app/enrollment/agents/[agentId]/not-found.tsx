// SPDX-License-Identifier: AGPL-3.0-only

import { MonitorOff } from "lucide-react";

import { ButtonLink } from "@/components/ui/button";
import { cardClass } from "@/components/ui/stat-tile";

export default function AgentNotFound() {
  return (
    <section className={`${cardClass} flex flex-col items-center gap-2 px-6 py-10 text-center`}>
      <span className="flex size-12 items-center justify-center rounded-full bg-(--primary-tint) text-(--primary-strong)">
        <MonitorOff size={22} aria-hidden="true" />
      </span>
      <h1 className="m-0 mt-1 text-base font-semibold text-(--ink)">Agent not found</h1>
      <p className="m-0 max-w-[420px] text-sm text-(--muted)">The agent may have been removed from this deployment, or the link is wrong.</p>
      <div className="mt-2">
        <ButtonLink href="/enrollment/agents">Back to agents</ButtonLink>
      </div>
    </section>
  );
}
