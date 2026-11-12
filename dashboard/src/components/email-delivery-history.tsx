// SPDX-License-Identifier: AGPL-3.0-only
"use client";

import { MailCheck, RefreshCw } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { formatMonitoringTimestamp, type AlertEmailDelivery } from "@/lib/monitoring-core";
import { alertEventWord, emailDeliveryWord } from "@/lib/monitoring-view-core";

import { DeliveryCard, DeliveryRow } from "./alerts/delivery-card";
import { Button } from "./ui/button";

export function EmailDeliveryHistory({
  initialDeliveries,
  canManage,
}: {
  initialDeliveries: AlertEmailDelivery[];
  canManage: boolean;
}) {
  const router = useRouter();
  const [deliveries, setDeliveries] = useState(initialDeliveries);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState("");

  async function retry(deliveryId: string) {
    setBusy(deliveryId);
    setError("");
    try {
      const response = await fetch(
        `/api/email-deliveries/${encodeURIComponent(deliveryId)}/retry`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ request_id: crypto.randomUUID().replaceAll("-", "") }),
        },
      );
      const body = await response.json().catch(() => null) as {
        delivery?: AlertEmailDelivery;
        error?: string;
      } | null;
      if (!response.ok || !body?.delivery) {
        throw new Error(body?.error ?? "The retry could not be confirmed.");
      }
      setDeliveries((current) => current.map((item) => (
        item.id === deliveryId ? body.delivery as AlertEmailDelivery : item
      )));
      router.refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The retry could not be confirmed.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <DeliveryCard
      title="Email"
      sub={`${deliveries.length} ${deliveries.length === 1 ? "email" : "emails"} for this alert. Sent means the mail service accepted it, not that it was read.`}
      icon={MailCheck}
      emptyTitle="No emails for this alert"
      emptyBody="Email alerts are switched off or not set up, or no change to this alert has been queued yet."
      error={error}
    >
      {deliveries.map((delivery) => (
        <DeliveryRow
          key={delivery.id}
          word={emailDeliveryWord(delivery.status)}
          title={<>To <span className="font-(family-name:--font-data)">{delivery.recipient}</span></>}
          detail={[
            `${alertEventWord(delivery.event_type)} · ${delivery.attempt_count} of ${delivery.max_attempts} automatic attempts`,
            delivery.last_error_code ? `Last error: ${delivery.last_error_code.replaceAll("_", " ")}` : null,
          ]}
          time={formatMonitoringTimestamp(delivery.sent_at ?? delivery.created_at)}
          attempts={delivery.attempts.map((attempt) => ({
            id: attempt.id,
            text: `Attempt ${attempt.attempt_number}: ${attempt.status}`,
            time: formatMonitoringTimestamp(attempt.completed_at ?? attempt.created_at),
          }))}
          action={
            delivery.status === "failed" && canManage ? (
              <Button size="compact" icon={RefreshCw} onClick={() => retry(delivery.id)} disabled={Boolean(busy)}>
                {busy === delivery.id ? "Queuing…" : "Send again"}
              </Button>
            ) : null
          }
        />
      ))}
    </DeliveryCard>
  );
}
