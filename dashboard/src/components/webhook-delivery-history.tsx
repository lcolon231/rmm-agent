// SPDX-License-Identifier: AGPL-3.0-only
"use client";

import { RefreshCw, Webhook } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { formatMonitoringTimestamp, type AlertWebhookDelivery } from "@/lib/monitoring-core";
import { alertEventWord, webhookDeliveryWord } from "@/lib/monitoring-view-core";

import { DeliveryCard, DeliveryRow } from "./alerts/delivery-card";
import { Button } from "./ui/button";

export function WebhookDeliveryHistory({
  initialDeliveries,
  canManage,
}: {
  initialDeliveries: AlertWebhookDelivery[];
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
        `/api/webhook-deliveries/${encodeURIComponent(deliveryId)}/retry`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ request_id: crypto.randomUUID().replaceAll("-", "") }),
        },
      );
      const body = await response.json().catch(() => null) as {
        delivery?: AlertWebhookDelivery;
        error?: string;
      } | null;
      if (!response.ok || !body?.delivery) {
        throw new Error(body?.error ?? "The retry could not be confirmed.");
      }
      setDeliveries((current) => current.map((item) => (
        item.id === deliveryId ? body.delivery as AlertWebhookDelivery : item
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
      title="Webhooks"
      sub={`${deliveries.length} signed ${deliveries.length === 1 ? "webhook" : "webhooks"} for this alert.`}
      icon={Webhook}
      emptyTitle="No webhooks for this alert"
      emptyBody="No webhook destination is subscribed to this kind of change, or the change was not sent."
      error={error}
    >
      {deliveries.map((delivery) => (
        <DeliveryRow
          key={delivery.id}
          word={webhookDeliveryWord(delivery.status)}
          title={<>{delivery.endpoint_name} · <span className="font-(family-name:--font-data)">{delivery.destination}</span></>}
          detail={[
            `${alertEventWord(delivery.event_type)} · ${delivery.attempt_count} of ${delivery.max_attempts} automatic attempts`,
            [
              delivery.last_http_status ? `Last response HTTP ${delivery.last_http_status}` : null,
              delivery.last_error_code ? `Last error: ${delivery.last_error_code.replaceAll("_", " ")}` : null,
            ].filter(Boolean).join(" · ") || null,
          ]}
          time={formatMonitoringTimestamp(delivery.delivered_at ?? delivery.created_at)}
          attempts={delivery.attempts.map((attempt) => ({
            id: attempt.id,
            text: `Attempt ${attempt.attempt_number}: ${attempt.status}${attempt.http_status ? ` · HTTP ${attempt.http_status}` : ""}${attempt.error_code ? ` · ${attempt.error_code.replaceAll("_", " ")}` : ""}`,
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
