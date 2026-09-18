// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import { MessageCircle } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

export function SupportChatLaunchButton({
  endpointId,
  capable,
  trusted,
  canOpen,
}: {
  endpointId: string;
  capable: boolean;
  trusted: boolean;
  canOpen: boolean;
}) {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const enabled = capable && trusted && canOpen;

  const open = async () => {
    if (!enabled || pending) return;
    setPending(true);
    setMessage(null);
    try {
      const response = await fetch(
        `/api/endpoints/${encodeURIComponent(endpointId)}/support-chat`,
        { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" },
      );
      const body = await response.json().catch(() => ({})) as { conversation_id?: unknown; error?: unknown };
      if (!response.ok || typeof body.conversation_id !== "string") {
        throw new Error(typeof body.error === "string" ? body.error : "NodeLink Support could not be started.");
      }
      router.push(`/support/${encodeURIComponent(body.conversation_id)}`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "NodeLink Support could not be started.");
    } finally {
      setPending(false);
    }
  };

  const title = !canOpen
    ? "Your role cannot start support chat"
    : !trusted
      ? "Support chat requires an active, trusted endpoint"
      : !capable
        ? "Update the endpoint agent to enable technician-initiated support chat"
        : "Open NodeLink Support on this endpoint";

  return (
    <div className="detail-chat-launch">
      <button type="button" className="detail-console-link" disabled={!enabled || pending} onClick={open} title={title}>
        <MessageCircle size={15} /> {pending ? "Starting support..." : "Start support chat"}
      </button>
      {message ? <small role="alert">{message}</small> : null}
    </div>
  );
}
