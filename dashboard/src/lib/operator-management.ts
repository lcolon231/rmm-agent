// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import type {
  OperatorCreateInput,
  OperatorRoleChangeInput,
  OperatorStatusChangeInput,
  ScriptPermissionInput,
} from "@/lib/operator-management-core";
import { nodelinkApiRequest } from "@/lib/nodelink-api";

export function listOperators(sessionToken: string): Promise<unknown> {
  return nodelinkApiRequest<unknown>("/api/v1/auth/operators", {
    method: "GET",
    sessionToken,
  });
}

export function createOperator(
  sessionToken: string,
  input: OperatorCreateInput,
): Promise<unknown> {
  return nodelinkApiRequest<unknown>("/api/v1/auth/operators", {
    body: JSON.stringify(input),
    headers: { "Content-Type": "application/json" },
    method: "POST",
    sessionToken,
  });
}

export function grantScriptPermission(
  sessionToken: string,
  operatorId: string,
  input: ScriptPermissionInput,
): Promise<unknown> {
  return nodelinkApiRequest<unknown>(
    `/api/v1/auth/operators/${encodeURIComponent(operatorId)}/script-permission`,
    {
      body: JSON.stringify(input),
      headers: { "Content-Type": "application/json" },
      method: "PUT",
      sessionToken,
    },
  );
}

export function revokeScriptPermission(
  sessionToken: string,
  operatorId: string,
  input: { reason: string },
): Promise<unknown> {
  return nodelinkApiRequest<unknown>(
    `/api/v1/auth/operators/${encodeURIComponent(operatorId)}/script-permission/revoke`,
    {
      body: JSON.stringify(input),
      headers: { "Content-Type": "application/json" },
      method: "POST",
      sessionToken,
    },
  );
}

export async function revokeManagedOperatorTokens(
  sessionToken: string,
  operatorId: string,
): Promise<void> {
  await nodelinkApiRequest<void>(
    `/api/v1/auth/operators/${encodeURIComponent(operatorId)}/revoke-tokens`,
    {
      method: "POST",
      sessionToken,
    },
  );
}

export function changeManagedOperatorRole(
  sessionToken: string,
  operatorId: string,
  input: OperatorRoleChangeInput,
): Promise<unknown> {
  return nodelinkApiRequest<unknown>(
    `/api/v1/auth/operators/${encodeURIComponent(operatorId)}/role`,
    {
      body: JSON.stringify(input),
      headers: { "Content-Type": "application/json" },
      method: "PUT",
      sessionToken,
    },
  );
}

export function changeManagedOperatorStatus(
  sessionToken: string,
  operatorId: string,
  input: OperatorStatusChangeInput,
): Promise<unknown> {
  return nodelinkApiRequest<unknown>(
    `/api/v1/auth/operators/${encodeURIComponent(operatorId)}/disabled`,
    {
      body: JSON.stringify(input),
      headers: { "Content-Type": "application/json" },
      method: "PUT",
      sessionToken,
    },
  );
}
