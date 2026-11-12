// SPDX-License-Identifier: AGPL-3.0-only
"use client";
import { useState, type ReactNode } from "react";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";

/** Shared typography for the existing administration forms and record cards. */
export function ManagedSurface({ children }: { children: ReactNode }) {
  return <div className="grid gap-6 text-sm text-(--slate) [&_section]:grid [&_section]:gap-4 [&_section]:rounded-[10px] [&_section]:border [&_section]:border-(--line) [&_section]:bg-(--paper) [&_section]:p-5 [&_header]:grid [&_header]:gap-2 [&_h1]:text-2xl [&_h1]:font-semibold [&_h1]:text-(--ink) [&_h2]:text-base [&_h2]:font-semibold [&_form]:grid [&_form]:gap-3 [&_label]:grid [&_label]:gap-2 [&_input:not([type=checkbox])]:min-h-10 [&_input:not([type=checkbox])]:rounded-lg [&_input:not([type=checkbox])]:border [&_input:not([type=checkbox])]:border-(--line-strong) [&_input:not([type=checkbox])]:px-3 [&_textarea]:rounded-lg [&_textarea]:border [&_textarea]:border-(--line-strong) [&_textarea]:p-3 [&_select]:min-h-10 [&_select]:rounded-lg [&_select]:border [&_select]:border-(--line-strong) [&_select]:px-3 [&_button]:min-h-10 [&_button]:rounded-lg [&_button]:border [&_button]:border-(--line-strong) [&_button]:px-4 [&_button]:disabled:opacity-50 [&_button]:focus-visible:outline-2 [&_button]:focus-visible:outline-(--focus) [&_small]:block [&_small]:text-xs [&_small]:text-(--muted) [&_ul]:grid [&_ul]:gap-3 [&_li]:rounded-lg [&_li]:border [&_li]:border-(--line) [&_li]:p-4 [&_code]:font-(family-name:--font-data) [&_code]:break-all [&_table]:w-full [&_table]:text-left [&_th]:bg-(--fog) [&_th]:p-3 [&_th]:text-xs [&_td]:border-t [&_td]:border-(--line) [&_td]:p-3 [&_a]:text-(--primary-strong) [&_[role=alert]]:rounded-lg [&_[role=alert]]:bg-(--amber-soft) [&_[role=alert]]:p-3 [&_[role=alert]]:text-[#89500b]">{children}</div>;
}

export function useReasonConfirmation() {
  const [pending, setPending] = useState<{ title: string; consequence: string; action: (reason: string) => Promise<void> } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return {
    ask: (title: string, consequence: string, action: (reason: string) => Promise<void>) => { setError(""); setPending({ title, consequence, action }); },
    dialog: <ConfirmDialog open={pending !== null} title={pending?.title ?? "Confirm action"} consequence={pending?.consequence ?? ""} confirmLabel="Confirm action" onCancel={() => setPending(null)} busy={busy} error={error || undefined} onConfirm={async (reason) => {
      if (reason.length < 3 || reason.length > 500) { setError("Use a reason between 3 and 500 characters."); return; }
      setBusy(true);
      try { await pending?.action(reason); setPending(null); } catch { setError("The change could not be confirmed. Refresh the records before retrying."); } finally { setBusy(false); }
    }} />,
  };
}
