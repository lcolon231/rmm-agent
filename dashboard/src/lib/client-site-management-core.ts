// SPDX-License-Identifier: AGPL-3.0-only

export type ClientCreateInput = { name: string };
export type SiteCreateInput = { client_id: string; name: string };

export type ClientRecord = {
  id: string;
  name: string;
  created_at: string;
};

export type SiteRecord = {
  id: string;
  client_id: string;
  name: string;
  created_at: string;
};

export function validateManagedName(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const name = value.trim();
  return name.length >= 1 && name.length <= 200 ? name : null;
}

export function validateClientCreateInput(value: unknown): ClientCreateInput | null {
  if (!value || typeof value !== "object") return null;
  const name = validateManagedName((value as Record<string, unknown>).name);
  return name ? { name } : null;
}

export function validateSiteCreateInput(value: unknown): SiteCreateInput | null {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  const name = validateManagedName(record.name);
  if (
    !name
    || typeof record.client_id !== "string"
    || record.client_id.trim().length < 1
    || record.client_id.trim().length > 36
  ) {
    return null;
  }
  return { client_id: record.client_id.trim(), name };
}

export function clientRecordFromUnknown(value: unknown): ClientRecord | null {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  if (
    typeof record.id !== "string"
    || record.id.length === 0
    || typeof record.name !== "string"
    || typeof record.created_at !== "string"
    || Number.isNaN(Date.parse(record.created_at))
  ) {
    return null;
  }
  return {
    id: record.id,
    name: record.name,
    created_at: record.created_at,
  };
}

export function siteRecordFromUnknown(value: unknown): SiteRecord | null {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  if (
    typeof record.id !== "string"
    || record.id.length === 0
    || typeof record.client_id !== "string"
    || record.client_id.length === 0
    || typeof record.name !== "string"
    || typeof record.created_at !== "string"
    || Number.isNaN(Date.parse(record.created_at))
  ) {
    return null;
  }
  return {
    id: record.id,
    client_id: record.client_id,
    name: record.name,
    created_at: record.created_at,
  };
}

export function describeClientSiteError(
  kind: "client" | "site",
  status: number,
  code: string | null,
): { message: string; status: number } {
  if (status === 401) {
    return { message: "Your session expired. Sign in again to continue setup.", status };
  }
  if (status === 403) {
    return {
      message: "Read-only operators cannot create clients or sites.",
      status,
    };
  }
  if (status === 404 && kind === "site") {
    return {
      message: "The selected client no longer exists. Refresh setup and choose another client.",
      status,
    };
  }
  if (status === 409) {
    if (code === "client_name_exists") {
      return { message: "A client with this name already exists.", status };
    }
    if (code === "site_name_exists") {
      return {
        message: "A site with this name already exists under the selected client.",
        status,
      };
    }
  }
  if (status === 400 || status === 422) {
    return {
      message: kind === "client"
        ? "Enter a client name between 1 and 200 characters."
        : "Select a client and enter a site name between 1 and 200 characters.",
      status: 400,
    };
  }
  return {
    message: `${kind === "client" ? "Client" : "Site"} creation is unavailable. Try again.`,
    status: 503,
  };
}
