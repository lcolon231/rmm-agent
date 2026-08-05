// SPDX-License-Identifier: AGPL-3.0-only
"use client";

import { MailCheck, RefreshCw } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import {
  formatAlertEventType,
  formatMonitoringTimestamp,
  type AlertEmailDelivery,
} from "@/lib/monitoring-core";

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
    <section className="enrollment-panel email-delivery-panel">
      <header>
        <div><span>Notification ledger</span><h2>{deliveries.length} email deliveries</h2></div>
        <MailCheck size={19} />
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
                <p>To {delivery.recipient} · generation {delivery.generation}</p>
                <small>
                  {delivery.attempt_count} of {delivery.max_attempts} automatic attempts
                  {delivery.last_error_code ? ` · ${delivery.last_error_code.replaceAll("_", " ")}` : ""}
                </small>
                {delivery.attempts.length ? (
                  <details>
                    <summary>Attempt history</summary>
                    <ol>{delivery.attempts.map((attempt) => (
                      <li key={attempt.id}>
                        <span>Attempt {attempt.attempt_number}: {attempt.status}</span>
                        <time>{formatMonitoringTimestamp(attempt.completed_at ?? attempt.created_at)}</time>
                      </li>
                    ))}</ol>
                  </details>
                ) : null}
              </div>
              <div className="email-delivery-meta">
                <time>{formatMonitoringTimestamp(delivery.sent_at ?? delivery.created_at)}</time>
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
          <MailCheck size={24} />
          <h3>No email deliveries</h3>
          <p>Notifications are disabled, invalid, or no transition has been queued yet.</p>
        </div>
      )}
      {error ? <p className="alert-action-error" role="alert">{error}</p> : null}
    </section>
  );
}
