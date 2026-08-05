// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import {
  monitoringPolicyDetailFromUnknown,
  monitoringPolicyListFromUnknown,
  alertEmailDeliveryFromUnknown,
  alertEmailDeliveryListFromUnknown,
  alertWebhookDeliveryFromUnknown,
  alertWebhookDeliveryListFromUnknown,
  alertAssigneesFromUnknown,
  monitoringAlertDetailFromUnknown,
  monitoringAlertListFromUnknown,
  webhookEndpointFromUnknown,
  webhookEndpointListFromUnknown,
  webhookEndpointSecretFromUnknown,
  webhookStatusFromUnknown,
  webhookValidationFromUnknown,
  type AlertActionInput,
  type AlertAssignee,
  type AlertEmailDelivery,
  type AlertWebhookDelivery,
  type MonitoringAlert,
  type MonitoringAlertDetail,
  type MonitoringPolicy,
  type MonitoringPolicyDetail,
  type WebhookDestinationValidation,
  type WebhookEndpoint,
  type WebhookEndpointSecret,
  type WebhookEventType,
  type WebhookStatus,
} from "@/lib/monitoring-core";
import { nodelinkApiRequest } from "@/lib/nodelink-api";

export async function getMonitoringPolicies(sessionToken: string): Promise<MonitoringPolicy[]> {
  const value = await nodelinkApiRequest<unknown>("/api/v1/monitoring/policies", {
    method: "GET",
    sessionToken,
  });
  const policies = monitoringPolicyListFromUnknown(value);
  if (!policies) throw new Error("The management service returned invalid monitoring policies.");
  return policies;
}

export async function getMonitoringPolicy(
  sessionToken: string,
  policyId: string,
): Promise<MonitoringPolicyDetail> {
  const value = await nodelinkApiRequest<unknown>(
    `/api/v1/monitoring/policies/${encodeURIComponent(policyId)}`,
    { method: "GET", sessionToken },
  );
  const policy = monitoringPolicyDetailFromUnknown(value);
  if (!policy) throw new Error("The management service returned an invalid monitoring policy.");
  return policy;
}

export async function getMonitoringAlerts(sessionToken: string): Promise<MonitoringAlert[]> {
  const value = await nodelinkApiRequest<unknown>("/api/v1/monitoring/alerts?limit=200", {
    method: "GET", sessionToken,
  });
  const alerts = monitoringAlertListFromUnknown(value);
  if (!alerts) throw new Error("The management service returned invalid monitoring alerts.");
  return alerts;
}

export async function getMonitoringAlert(
  sessionToken: string, alertId: string,
): Promise<MonitoringAlertDetail> {
  const value = await nodelinkApiRequest<unknown>(
    `/api/v1/monitoring/alerts/${encodeURIComponent(alertId)}`,
    { method: "GET", sessionToken },
  );
  const alert = monitoringAlertDetailFromUnknown(value);
  if (!alert) throw new Error("The management service returned an invalid monitoring alert.");
  return alert;
}

export async function getAlertAssignees(sessionToken: string): Promise<AlertAssignee[]> {
  const value = await nodelinkApiRequest<unknown>("/api/v1/monitoring/alert-assignees", {
    method: "GET", sessionToken,
  });
  const assignees = alertAssigneesFromUnknown(value);
  if (!assignees) throw new Error("The management service returned invalid alert assignees.");
  return assignees;
}

export function performAlertAction(
  sessionToken: string,
  alertId: string,
  action: "acknowledge" | "assign" | "comments" | "resolve",
  input: AlertActionInput,
): Promise<unknown> {
  return nodelinkApiRequest<unknown>(
    `/api/v1/monitoring/alerts/${encodeURIComponent(alertId)}/${action}`,
    {
      body: JSON.stringify(input), headers: { "Content-Type": "application/json" },
      method: "POST", sessionToken,
    },
  );
}

export async function getAlertEmailDeliveries(
  sessionToken: string,
  alertId: string,
): Promise<AlertEmailDelivery[]> {
  const value = await nodelinkApiRequest<unknown>(
    `/api/v1/monitoring/alerts/${encodeURIComponent(alertId)}/email-deliveries`,
    { method: "GET", sessionToken },
  );
  const deliveries = alertEmailDeliveryListFromUnknown(value);
  if (!deliveries) throw new Error("The management service returned invalid email delivery history.");
  return deliveries;
}

export async function retryAlertEmailDelivery(
  sessionToken: string,
  deliveryId: string,
  requestId: string,
): Promise<AlertEmailDelivery> {
  const value = await nodelinkApiRequest<unknown>(
    `/api/v1/monitoring/email-deliveries/${encodeURIComponent(deliveryId)}/retry`,
    {
      body: JSON.stringify({ request_id: requestId }),
      headers: { "Content-Type": "application/json" },
      method: "POST",
      sessionToken,
    },
  );
  const delivery = alertEmailDeliveryFromUnknown(value);
  if (!delivery) throw new Error("The management service returned an invalid email delivery.");
  return delivery;
}

export async function getWebhookStatus(sessionToken: string): Promise<WebhookStatus> {
  const value = await nodelinkApiRequest<unknown>("/api/v1/monitoring/webhooks/status", {
    method: "GET", sessionToken,
  });
  const status = webhookStatusFromUnknown(value);
  if (!status) throw new Error("The management service returned an invalid webhook status.");
  return status;
}

export async function getWebhookEndpoints(sessionToken: string): Promise<WebhookEndpoint[]> {
  const value = await nodelinkApiRequest<unknown>("/api/v1/monitoring/webhook-endpoints", {
    method: "GET", sessionToken,
  });
  const endpoints = webhookEndpointListFromUnknown(value);
  if (!endpoints) throw new Error("The management service returned invalid webhook endpoints.");
  return endpoints;
}

export async function createWebhookEndpoint(
  sessionToken: string,
  input: { name: string; url: string; event_types: WebhookEventType[] },
): Promise<WebhookEndpointSecret> {
  const value = await nodelinkApiRequest<unknown>("/api/v1/monitoring/webhook-endpoints", {
    body: JSON.stringify(input), headers: { "Content-Type": "application/json" },
    method: "POST", sessionToken,
  });
  const endpoint = webhookEndpointSecretFromUnknown(value);
  if (!endpoint) throw new Error("The management service returned an invalid webhook endpoint.");
  return endpoint;
}

export async function updateWebhookEndpoint(
  sessionToken: string,
  endpointId: string,
  input: {
    request_id: string;
    expected_version: number;
    name?: string;
    url?: string;
    event_types?: WebhookEventType[];
    enabled?: boolean;
  },
): Promise<WebhookEndpoint> {
  const value = await nodelinkApiRequest<unknown>(
    `/api/v1/monitoring/webhook-endpoints/${encodeURIComponent(endpointId)}`,
    {
      body: JSON.stringify(input), headers: { "Content-Type": "application/json" },
      method: "PUT", sessionToken,
    },
  );
  const endpoint = webhookEndpointFromUnknown(value);
  if (!endpoint) throw new Error("The management service returned an invalid webhook endpoint.");
  return endpoint;
}

export async function validateWebhookEndpoint(
  sessionToken: string, endpointId: string,
): Promise<WebhookDestinationValidation> {
  const value = await nodelinkApiRequest<unknown>(
    `/api/v1/monitoring/webhook-endpoints/${encodeURIComponent(endpointId)}/validate`,
    { method: "POST", sessionToken },
  );
  const validation = webhookValidationFromUnknown(value);
  if (!validation) throw new Error("The management service returned invalid validation evidence.");
  return validation;
}

export async function rotateWebhookSecret(
  sessionToken: string, endpointId: string, requestId: string, expectedVersion: number,
): Promise<WebhookEndpointSecret> {
  const value = await nodelinkApiRequest<unknown>(
    `/api/v1/monitoring/webhook-endpoints/${encodeURIComponent(endpointId)}/rotate-secret`,
    {
      body: JSON.stringify({ request_id: requestId, expected_version: expectedVersion }),
      headers: { "Content-Type": "application/json" }, method: "POST", sessionToken,
    },
  );
  const endpoint = webhookEndpointSecretFromUnknown(value);
  if (!endpoint) throw new Error("The management service returned an invalid rotated secret.");
  return endpoint;
}

export function deleteWebhookEndpoint(
  sessionToken: string, endpointId: string, requestId: string, expectedVersion: number,
): Promise<unknown> {
  const query = new URLSearchParams({
    request_id: requestId, expected_version: String(expectedVersion),
  });
  return nodelinkApiRequest<unknown>(
    `/api/v1/monitoring/webhook-endpoints/${encodeURIComponent(endpointId)}?${query}`,
    { method: "DELETE", sessionToken },
  );
}

export async function getAlertWebhookDeliveries(
  sessionToken: string, alertId: string,
): Promise<AlertWebhookDelivery[]> {
  const value = await nodelinkApiRequest<unknown>(
    `/api/v1/monitoring/alerts/${encodeURIComponent(alertId)}/webhook-deliveries`,
    { method: "GET", sessionToken },
  );
  const deliveries = alertWebhookDeliveryListFromUnknown(value);
  if (!deliveries) throw new Error("The management service returned invalid webhook history.");
  return deliveries;
}

export async function retryAlertWebhookDelivery(
  sessionToken: string, deliveryId: string, requestId: string,
): Promise<AlertWebhookDelivery> {
  const value = await nodelinkApiRequest<unknown>(
    `/api/v1/monitoring/webhook-deliveries/${encodeURIComponent(deliveryId)}/retry`,
    {
      body: JSON.stringify({ request_id: requestId }),
      headers: { "Content-Type": "application/json" }, method: "POST", sessionToken,
    },
  );
  const delivery = alertWebhookDeliveryFromUnknown(value);
  if (!delivery) throw new Error("The management service returned an invalid webhook delivery.");
  return delivery;
}
