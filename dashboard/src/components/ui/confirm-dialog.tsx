// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { TriangleAlert } from "lucide-react";
import { useId, useRef, useState, type FormEvent } from "react";

import { Button } from "./button";
import { Textarea } from "./field";
import { useModal } from "./use-modal";

type ConfirmDialogProps = {
  open: boolean;
  onCancel: () => void;
  /** Receives the trimmed reason, which belongs in the audit record. */
  onConfirm: (reason: string) => void | Promise<void>;
  /** The question, e.g. "Restart PHX-FD-02?" */
  title: string;
  /** One or two plain sentences on the consequence. */
  consequence: string;
  /** Names the action, e.g. "Restart device". */
  confirmLabel: string;
  busy?: boolean;
  error?: string;
};

/**
 * Every high-risk action goes through here. Confirm stays disabled until a
 * reason is given, because the reason is kept in the audit record.
 */
export function ConfirmDialog(props: ConfirmDialogProps) {
  if (!props.open) return null;
  // Mounting fresh on each open resets the reason without an effect.
  return <ConfirmDialogPanel {...props} />;
}

function ConfirmDialogPanel({ onCancel, onConfirm, title, consequence, confirmLabel, busy = false, error }: ConfirmDialogProps) {
  const [reason, setReason] = useState("");
  const reasonRef = useRef<HTMLTextAreaElement>(null);
  const panelRef = useModal(true, busy ? () => {} : onCancel, reasonRef);
  const titleId = useId();
  const bodyId = useId();
  const trimmed = reason.trim();

  function submit(event: FormEvent) {
    event.preventDefault();
    if (!trimmed || busy) return;
    void onConfirm(trimmed);
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4">
      <div aria-hidden="true" className="absolute inset-0 bg-[rgb(23_19_42/45%)]" onClick={busy ? undefined : onCancel} />
      <div
        ref={panelRef}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={bodyId}
        className="relative w-[min(480px,100%)] rounded-[10px] bg-(--paper) shadow-[0_14px_34px_rgb(24_16_46/12%)]"
      >
        <form onSubmit={submit}>
          <div className="grid gap-4 p-6">
            <span className="flex size-10 items-center justify-center rounded-full bg-(--amber-soft) text-[#89500b]">
              <TriangleAlert size={20} aria-hidden="true" />
            </span>
            <div className="grid gap-2">
              <h2 id={titleId} className="m-0 text-lg leading-[1.3] font-semibold text-(--ink)">
                {title}
              </h2>
              <p id={bodyId} className="m-0 text-sm leading-normal text-(--slate)">
                {consequence}
              </p>
            </div>
            <Textarea
              ref={reasonRef}
              label="Reason (kept in the audit record)"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              required
              disabled={busy}
              error={error}
            />
          </div>
          <footer className="flex flex-wrap justify-end gap-2 border-t border-(--line) px-6 py-4">
            <Button onClick={onCancel} disabled={busy}>
              Cancel
            </Button>
            <Button type="submit" variant="danger" disabled={!trimmed || busy} aria-busy={busy || undefined}>
              {confirmLabel}
            </Button>
          </footer>
        </form>
      </div>
    </div>
  );
}
