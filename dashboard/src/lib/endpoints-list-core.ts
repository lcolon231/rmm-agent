// SPDX-License-Identifier: AGPL-3.0-only

/**
 * URL state for the Endpoints list. Filters, search and page live in the
 * query string so a view can be shared and the back button works.
 */

export type EndpointStatusFilter = "online" | "offline" | "pending";

export type EndpointsQuery = {
  client?: string;
  site?: string;
  status?: EndpointStatusFilter;
  search?: string;
  page: number;
};

type Raw = Record<string, string | string[] | undefined>;

const ID = /^[A-Za-z0-9-]{1,36}$/;

function single(value: string | string[] | undefined): string | undefined {
  return typeof value === "string" ? value : undefined;
}

export function parseEndpointsQuery(raw: Raw): EndpointsQuery {
  const status = single(raw.status);
  const page = single(raw.page);
  const search = single(raw.search)?.trim().slice(0, 100);
  const client = single(raw.client);
  const site = single(raw.site);
  return {
    client: client && ID.test(client) ? client : undefined,
    site: site && ID.test(site) ? site : undefined,
    status: status === "online" || status === "offline" || status === "pending" ? status : undefined,
    search: search || undefined,
    page: page && /^\d{1,6}$/.test(page) ? Math.max(1, Number(page)) : 1,
  };
}

/**
 * The href for this list with some state changed. Changing anything but the
 * page returns to page 1, because the old page may no longer exist.
 */
export function endpointsHref(current: EndpointsQuery, changes: Partial<EndpointsQuery>): string {
  const next = { ...current, ...changes };
  if (!("page" in changes)) next.page = 1;
  const params = new URLSearchParams();
  if (next.client) params.set("client", next.client);
  if (next.site) params.set("site", next.site);
  if (next.status) params.set("status", next.status);
  if (next.search) params.set("search", next.search);
  if (next.page > 1) params.set("page", String(next.page));
  const query = params.toString();
  return query ? `/endpoints?${query}` : "/endpoints";
}

/** CSV cell that a spreadsheet will not run as a formula. */
export function csvCell(value: string | number | null | undefined): string {
  let text = value === null || value === undefined ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}
