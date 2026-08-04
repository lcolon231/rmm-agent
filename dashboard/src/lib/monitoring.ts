// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import {
  monitoringPolicyDetailFromUnknown,
  monitoringPolicyListFromUnknown,
  alertAssigneesFromUnknown,
  monitoringAlertDetailFromUnknown,
  monitoringAlertListFromUnknown,
  type AlertActionInput,
  type AlertAssignee,
  type MonitoringAlert,
  type MonitoringAlertDetail,
  type MonitoringPolicy,
  type MonitoringPolicyDetail,
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
