// SPDX-License-Identifier: AGPL-3.0-only

import Link from "next/link";
import type { ReactNode } from "react";

import { cx, focusRing } from "../ui/cx";

/** Rendered inside the app shell, so it is a section, not a second <main>. */
export function NotFoundPanel({ title, body, href, linkLabel, role }: { title: string; body: ReactNode; href: string; linkLabel: string; role?: "alert" }) {
  return (
    <section role={role} className="grid max-w-[640px] gap-2 rounded-[10px] border border-(--line) bg-(--paper) p-6">
      <h1 className="m-0 text-2xl font-semibold text-(--ink)">{title}</h1>
      <p className="m-0 text-sm text-(--slate)">{body}</p>
      <p className="m-0 mt-2 text-sm font-semibold">
        <Link href={href} className={cx("rounded text-(--primary-strong) no-underline hover:underline", focusRing)}>
          {linkLabel}
        </Link>
      </p>
    </section>
  );
}
