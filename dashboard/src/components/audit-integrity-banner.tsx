// SPDX-License-Identifier: AGPL-3.0-only

import { CircleAlert, HelpCircle, ShieldCheck } from "lucide-react";

import type { AuditStatement } from "@/lib/audit-core";

const icons = {
  failed: CircleAlert,
  unknown: HelpCircle,
  verified: ShieldCheck,
};

/**
 * One integrity statement.
 *
 * A failed statement is announced to assistive technology as an alert rather
 * than a status, because a broken chain is the one thing on this page an
 * operator must not scroll past.
 */
export function AuditIntegrityBanner({ statement }: { statement: AuditStatement }) {
  const Icon = icons[statement.tone];
  return (
    <div
      className={`audit-banner ${statement.tone}`}
      role={statement.tone === "failed" ? "alert" : "status"}
    >
      <Icon aria-hidden="true" size={20} />
      <div>
        <strong>{statement.headline}</strong>
        <span>{statement.detail}</span>
      </div>
    </div>
  );
}
