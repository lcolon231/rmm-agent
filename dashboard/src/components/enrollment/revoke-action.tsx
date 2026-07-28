// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { ShieldOff, X } from "lucide-react";
import { useRouter } from "next/navigation";
import { useId, useRef, useState } from "react";

export function RevokeAction({
  endpoint,
  label,
  subject,
}: {
  endpoint: string;
  label: string;
  subject: string;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const reasonId = useId();
  const router = useRouter();
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);

  async function revoke() {
    if (reason.trim().length < 3) {
      setError("Enter a reason of at least three characters.");
      return;
    }
    setPending(true);
    setError("");
    try {
      const response = await fetch(endpoint, {
        body: JSON.stringify({ reason: reason.trim() }),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      if (!response.ok) {
        const body = await response.json().catch(() => null) as { error?: string } | null;
        setError(body?.error ?? "Revocation failed. Try again.");
        return;
      }
      dialog.current?.close();
      router.refresh();
    } catch {
      setError("Revocation failed. Check the management service and try again.");
    } finally {
      setPending(false);
    }
  }

  return (
    <>
      <button className="enrollment-danger-link" onClick={() => dialog.current?.showModal()} type="button">
        <ShieldOff size={15} /> {label}
      </button>
      <dialog className="enrollment-dialog" ref={dialog}>
        <div className="enrollment-dialog-head">
          <div><span>Trust change</span><h2>{label}</h2></div>
          <button aria-label="Close dialog" onClick={() => dialog.current?.close()} type="button"><X size={18} /></button>
        </div>
        <p>This immediately revokes <strong>{subject}</strong>. The audit log will retain the record.</p>
        <label htmlFor={reasonId}>Reason</label>
        <textarea id={reasonId} maxLength={500} onChange={(event) => setReason(event.target.value)} rows={3} value={reason} />
        {error ? <p className="enrollment-form-error" role="alert">{error}</p> : null}
        <div className="enrollment-dialog-actions">
          <button onClick={() => dialog.current?.close()} type="button">Cancel</button>
          <button className="danger" disabled={pending} onClick={revoke} type="button">{pending ? "Revoking…" : label}</button>
        </div>
      </dialog>
    </>
  );
}
