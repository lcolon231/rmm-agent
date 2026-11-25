// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Pure helpers behind the New schedule drawer and the schedule list (issue #358).
 *
 * Hiding a script here is a convenience; the management service refuses a
 * schedule pinned to an unapproved or retired version on its own.
 */

import type { ScheduledTaskTargetType } from "./scheduled-tasks-core.ts";
import type { ScriptItem, ScriptLanguage } from "./script-library-core.ts";

/** Library scripts a schedule may run unattended for the given kind. Scripts
 * with a required parameter are left out: schedules carry no parameter values. */
export function schedulableScripts(items: readonly ScriptItem[], kind: ScriptLanguage): ScriptItem[] {
  return items.filter((item) =>
    item.deprecated_at === null
    && item.latest.review?.state === "approved"
    && item.latest.language === kind
    && !item.latest.parameters.some((parameter) => parameter.required));
}

/** The part of the client navigation response the site picker needs. */
export type NavigationClients = {
  items: ReadonlyArray<{ name: string; sites: ReadonlyArray<{ id: string; name: string }> }>;
};

export type ScheduleOption = { id: string; label: string };

export type SiteOptionGroup = { client: string; options: ScheduleOption[] };

/** Visible sites grouped by client, labelled "Client — Site" so same-named
 * sites at different clients stay distinguishable. Clients without sites are dropped. */
export function siteOptionGroups(navigation: NavigationClients): SiteOptionGroup[] {
  return navigation.items
    .filter((client) => client.sites.length > 0)
    .map((client) => ({
      client: client.name,
      options: client.sites.map((site) => ({ id: site.id, label: `${client.name} — ${site.name}` })),
    }));
}

/** What the schedules page loads for the drawer's pickers and for naming
 * targets and scripts. Each is null when it could not be loaded. */
export type ScheduleSources = {
  scripts: ScriptItem[] | null;
  sites: SiteOptionGroup[] | null;
  endpoints: ScheduleOption[] | null;
};

export const NO_SCHEDULE_SOURCES: ScheduleSources = { scripts: null, sites: null, endpoints: null };

/** Display names by id. Only each script's latest version is known from the
 * list API, so a schedule pinned to an older version falls back to its raw ID. */
export function scheduleDisplayNames(sources: ScheduleSources) {
  const sites = new Map((sources.sites ?? []).flatMap((group) => group.options).map((site) => [site.id, site.label]));
  const endpoints = new Map((sources.endpoints ?? []).map((endpoint) => [endpoint.id, endpoint.label]));
  const scripts = new Map((sources.scripts ?? []).map((item) => [item.latest.id, `${item.name} · v${item.latest.version}`]));
  return {
    target: (targetType: ScheduledTaskTargetType, id: string) => (targetType === "site" ? sites : endpoints).get(id) ?? null,
    script: (versionId: string) => scripts.get(versionId) ?? null,
  };
}
