// SPDX-License-Identifier: AGPL-3.0-only

import "server-only";

import {
  maintenanceWindowFromUnknown,
  maintenanceWindowListFromUnknown,
  type MaintenanceWindow,
  type MaintenanceWindowCreateRequest,
} from "@/lib/maintenance-windows-core";
import { nodelinkApiRequest } from "@/lib/nodelink-api";

export async function getMaintenanceWindows(sessionToken: string): Promise<MaintenanceWindow[]> {
  const value = await nodelinkApiRequest<unknown>("/api/v1/monitoring/maintenance-windows", {
    method: "GET",
    sessionToken,
  });
  const windows = maintenanceWindowListFromUnknown(value);
  if (!windows) throw new Error("The management service returned invalid maintenance windows.");
  return windows;
}

export async function createMaintenanceWindow(
  sessionToken: string,
  input: MaintenanceWindowCreateRequest,
): Promise<MaintenanceWindow> {
  const value = await nodelinkApiRequest<unknown>("/api/v1/monitoring/maintenance-windows", {
    body: JSON.stringify(input),
    headers: { "Content-Type": "application/json" },
    method: "POST",
    sessionToken,
  });
  const window = maintenanceWindowFromUnknown(value);
  if (!window) throw new Error("The management service returned an invalid maintenance window.");
  return window;
}

export function deleteMaintenanceWindow(
  sessionToken: string,
  windowId: string,
): Promise<unknown> {
  return nodelinkApiRequest<unknown>(
    `/api/v1/monitoring/maintenance-windows/${encodeURIComponent(windowId)}`,
    { method: "DELETE", sessionToken },
  );
}
