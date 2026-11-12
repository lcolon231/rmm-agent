// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { ShieldOff } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { useReportModal } from "@/components/admin/admin-ui";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { reasonProblem } from "@/lib/admin-screens-core";

const CONSEQUENCE = {
  agent: "Its credentials stop working permanently and any queued commands are expired. To manage the device again it has to be enrolled again.",
  token: "It can no longer be used to add devices. Devices already enrolled with it are not affected.",
} as const;

/**
 * High-risk revocation of an agent or an enrollment token. The reason is
 * required (3–500 characters) and sent to the API, which keeps it in the
 * audit record.
 */
export function RevokeAction({
  endpoint,
  kind,
  label,
  subject,
  onRevoked,
}: {
  endpoint: string;
  kind: keyof typeof CONSEQUENCE;
  label: string;
  subject: string;
  onRevoked?: () => void;
}) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  useReportModal(open);

  async function revoke(reason: string) {
    const problem = reasonProblem(reason);
    if (problem) {
      setError(problem);
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
        setError(`${body?.error ?? "Revocation failed. Try again."} Nothing was changed.`);
        return;
      }
      setOpen(false);
      onRevoked?.();
      router.refresh();
    } catch {
      setError("The revocation result could not be confirmed. Refresh the record before retrying.");
    } finally {
      setPending(false);
    }
  }

  return (
    <>
      <Button
        variant="danger"
        icon={ShieldOff}
        onClick={() => {
          setError("");
          setOpen(true);
        }}
      >
        {label}
      </Button>
      <ConfirmDialog
        open={open}
        onCancel={() => setOpen(false)}
        onConfirm={revoke}
        title={`Revoke ${subject}?`}
        consequence={CONSEQUENCE[kind]}
        confirmLabel={label}
        busy={pending}
        error={error || undefined}
      />
    </>
  );
}

