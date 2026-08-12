// SPDX-License-Identifier: AGPL-3.0-only

import { CalendarClock } from "lucide-react";
import { redirect } from "next/navigation";

import {
  MaintenanceWindowManager,
  type MaintenanceWindowPrefill,
  type ScopeTargetOption,
} from "@/components/maintenance-window-manager";
import { getClientNavigation } from "@/lib/client-navigation";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getEndpointList } from "@/lib/endpoint-list";
import { getMaintenanceWindows } from "@/lib/maintenance-windows";
import { safeReturnPath, type MaintenanceWindow } from "@/lib/maintenance-windows-core";
import type { MonitoringScope } from "@/lib/monitoring-core";

export const dynamic = "force-dynamic";

type Query = Record<string, string | string[] | undefined>;

function single(value: string | string[] | undefined): string | null {
  if (typeof value === "string") return value;
  return Array.isArray(value) && typeof value[0] === "string" ? value[0] : null;
}

function readPrefill(query: Query): MaintenanceWindowPrefill {
  const scope = single(query.scope);
  const coverSeconds = Number(single(query.cover_seconds));
  const name = single(query.name);
  return {
    scope: ["global", "client", "site", "agent"].includes(scope ?? "")
      ? (scope as MonitoringScope)
      : null,
    scopeId: single(query.scope_id)?.slice(0, 36) ?? null,
    name: name ? name.slice(0, 200) : null,
    coverSeconds: Number.isInteger(coverSeconds) && coverSeconds > 0 && coverSeconds <= 3600
      ? coverSeconds
      : null,
    returnPath: safeReturnPath(single(query.return)),
  };
}

export default async function MaintenanceWindowsPage({
  searchParams,
}: {
  searchParams: Promise<Query>;
}) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  const prefill = readPrefill(await searchParams);
  const [windowResult, navigationResult, endpointResult] = await Promise.allSettled([
    getMaintenanceWindows(session.sessionToken),
    getClientNavigation(session.sessionToken),
    getEndpointList(session.sessionToken, { sort: "hostname", direction: "asc" }),
  ]);

  const windows: MaintenanceWindow[] | null =
    windowResult.status === "fulfilled" ? windowResult.value : null;

  const clients: ScopeTargetOption[] = [];
  const sites: ScopeTargetOption[] = [];
  if (navigationResult.status === "fulfilled") {
    for (const client of navigationResult.value.items) {
      clients.push({ id: client.id, label: client.name, hint: `${client.sites.length} sites` });
      for (const site of client.sites) {
        sites.push({ id: site.id, label: site.name, hint: client.name });
      }
    }
  }
  const endpoints: ScopeTargetOption[] =
    endpointResult.status === "fulfilled"
      ? endpointResult.value.items.map((item) => ({
          id: item.id,
          label: item.hostname,
          hint: `${item.client_name} · ${item.site_name}`,
        }))
      : [];

  // The render instant seeds the form and the first coverage reading. It is
  // serialized to the client, which then follows its own clock, so hydration
  // never recomputes it.
  // eslint-disable-next-line react-hooks/purity
  const renderedAt = Date.now();

  return (
    <>
      <header className="enrollment-page-head">
        <div>
          <span>Change control</span>
          <h1>Maintenance windows</h1>
          <p>
            A window is the prerequisite the management service enforces before it will sign a
            restart or shutdown, and it suppresses alerting for everything it covers. Nothing here
            weakens that check — the server re-evaluates coverage when the command is signed.
          </p>
        </div>
        <span className="webhook-version-mark"><CalendarClock size={15} /> Server-enforced</span>
      </header>

      {windows === null ? (
        <div className="enrollment-empty" role="alert">
          <CalendarClock size={26} />
          <h3>Maintenance windows could not be loaded</h3>
          <p>No windows are shown because the management service response could not be verified.</p>
        </div>
      ) : (
        <MaintenanceWindowManager
          canManage={session.operator.role !== "readonly"}
          clients={clients}
          endpoints={endpoints}
          initialWindows={windows}
          prefill={prefill}
          serverNowMs={renderedAt}
          sites={sites}
        />
      )}
    </>
  );
}
