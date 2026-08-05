// SPDX-License-Identifier: AGPL-3.0-only
"use client";

import { RefreshCw, Webhook } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import {
  formatAlertEventType,
  formatMonitoringTimestamp,
  type AlertWebhookDelivery,
} from "@/lib/monitoring-core";

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
    <section className="enrollment-panel email-delivery-panel webhook-delivery-panel">
      <header>
        <div><span>Signed event ledger</span><h2>{deliveries.length} webhook deliveries</h2></div>
        <Webhook size={19} />
      </header>
      {deliveries.length ? (
        <div className="email-delivery-ledger">
          {deliveries.map((delivery) => (
            <article key={delivery.id} className={delivery.status}>
              <span className="email-delivery-rail" aria-hidden="true" />
              <div className="email-delivery-copy">
                <div>
                  <strong>{formatAlertEventType(delivery.event_type)}</strong>
                  <span className={`email-delivery-status ${delivery.status}`}>{delivery.status}</span>
                </div>
                <p>{delivery.endpoint_name} · {delivery.destination} · generation {delivery.generation}</p>
                <small>
                  Delivery {delivery.id.slice(0, 8)}… · {delivery.attempt_count} of {delivery.max_attempts} automatic attempts
                  {delivery.last_http_status ? ` · HTTP ${delivery.last_http_status}` : ""}
                  {delivery.last_error_code ? ` · ${delivery.last_error_code.replaceAll("_", " ")}` : ""}
                </small>
                {delivery.attempts.length ? (
                  <details>
                    <summary>Attempt history</summary>
                    <ol>{delivery.attempts.map((attempt) => (
                      <li key={attempt.id}>
                        <span>Attempt {attempt.attempt_number}: {attempt.status}{attempt.http_status ? ` · HTTP ${attempt.http_status}` : ""}{attempt.error_code ? ` · ${attempt.error_code.replaceAll("_", " ")}` : ""}</span>
                        <time>{formatMonitoringTimestamp(attempt.completed_at ?? attempt.created_at)}</time>
                      </li>
                    ))}</ol>
                  </details>
                ) : null}
              </div>
              <div className="email-delivery-meta">
                <time>{formatMonitoringTimestamp(delivery.delivered_at ?? delivery.created_at)}</time>
                {delivery.status === "failed" && canManage ? (
                  <button type="button" onClick={() => retry(delivery.id)} disabled={Boolean(busy)}>
                    <RefreshCw size={13} />{busy === delivery.id ? "Queuing…" : "Retry"}
                  </button>
                ) : null}
              </div>
            </article>
          ))}
        </div>
      ) : (
        <div className="enrollment-empty">
          <Webhook size={24} />
          <h3>No webhook deliveries</h3>
          <p>No destination subscribed to this alert transition, or the transition was suppressed.</p>
        </div>
      )}
      {error ? <p className="alert-action-error" role="alert">{error}</p> : null}
    </section>
  );
}
