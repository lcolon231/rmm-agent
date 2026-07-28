// SPDX-License-Identifier: AGPL-3.0-only

import type { DashboardRole } from "@/lib/dashboard-auth-core";

export type EnrollmentTokenStatus = "active" | "used" | "expired" | "revoked";

export function canManageEnrollment(role: DashboardRole): boolean {
  return role === "operator" || role === "admin";
}

export function statusLabel(status: EnrollmentTokenStatus): string {
  return {
    active: "Active",
    used: "Used",
    expired: "Expired",
    revoked: "Revoked",
  }[status];
}

export function formatEnrollmentDateTime(
  value: string | null,
  fallback = "Never",
  includeSeconds = false,
): string {
  if (!value) return fallback;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return fallback;
  return new Intl.DateTimeFormat("en-US", {
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    month: "short",
    second: includeSeconds ? "2-digit" : undefined,
    timeZone: "UTC",
    timeZoneName: "short",
    year: "numeric",
  }).format(date);
}

export function maskEnrollmentToken(prefix: string): string {
  const safePrefix = prefix.trim().slice(0, 12) || "nlenr";
  return `${safePrefix}••••••••`;
}

export type CreateEnrollmentTokenInput = {
  site_id: string;
  name: string;
  description?: string;
  assigned_user_id?: string;
  environment?: string;
  hostname_restriction?: string;
  agent_name_restriction?: string;
  labels: string[];
  expires_at: string;
  max_uses: number;
  notes?: string;
};

export function createTokenInputFromForm(formData: FormData): CreateEnrollmentTokenInput | null {
  const siteId = String(formData.get("site_id") ?? "").trim();
  const name = String(formData.get("name") ?? "").trim();
  const expiryValue = String(formData.get("expires_at") ?? "").trim();
  const maxUses = Number(formData.get("max_uses"));
  if (!siteId || !name || name.length > 200 || !expiryValue || !Number.isInteger(maxUses) || maxUses < 1 || maxUses > 100) {
    return null;
  }
  const expiresAt = new Date(expiryValue);
  if (Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() <= Date.now()) {
    return null;
  }
  const optional = (key: string) => {
    const value = String(formData.get(key) ?? "").trim();
    return value || undefined;
  };
  const labels = String(formData.get("labels") ?? "")
    .split(",")
    .map((label) => label.trim())
    .filter(Boolean);
  if (labels.length > 20 || new Set(labels.map((label) => label.toLowerCase())).size !== labels.length) {
    return null;
  }
  return {
    site_id: siteId,
    name,
    description: optional("description"),
    assigned_user_id: optional("assigned_user_id"),
    environment: optional("environment"),
    hostname_restriction: optional("hostname_restriction"),
    agent_name_restriction: optional("agent_name_restriction"),
    labels,
    expires_at: expiresAt.toISOString(),
    max_uses: maxUses,
    notes: optional("notes"),
  };
}
