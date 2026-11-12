// SPDX-License-Identifier: AGPL-3.0-only

import { CircleAlert, Clock, HardDrive, Layers, ListX } from "lucide-react";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";

import { InventorySectionCard } from "@/components/endpoint/inventory-section-card";
import { EndpointSectionHeader, Notice, PageFailure, Panel } from "@/components/endpoint/section-header";
import { PageStack } from "@/components/shell/page-header";
import { cardClass, StatRow, StatTile } from "@/components/ui/stat-tile";
import { EmptyState } from "@/components/ui/states";
import { WindowsUpdateInstallation } from "@/components/windows-update-installation";
import { formatEndpointDateTime } from "@/lib/endpoint-detail-core";
import {
  sectionLabel,
  statusTone,
  type InventoryRecord,
} from "@/lib/inventory-core";
import { getEndpointInventory } from "@/lib/inventory";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getEndpointDetail, type EndpointDetailData } from "@/lib/endpoint-detail";
import { NodelinkApiError } from "@/lib/nodelink-api";
import {
  windowsUpdateScanIsStale,
  windowsUpdatesFromUnknown,
} from "@/lib/windows-updates-core";

export const dynamic = "force-dynamic";

export default async function EndpointInventoryPage({
  params,
}: {
  params: Promise<{ endpointId: string }>;
}) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");

  const { endpointId } = await params;

  let inventory: InventoryRecord | null = null;
  let endpoint: EndpointDetailData | null = null;
  let loadFailed = false;
  try {
    [inventory, endpoint] = await Promise.all([
      getEndpointInventory(session.sessionToken, endpointId),
      getEndpointDetail(session.sessionToken, endpointId, { historyHours: 1, historyLimit: 10 }),
    ]);
  } catch (error) {
    if (error instanceof NodelinkApiError && error.status === 404) notFound();
    loadFailed = true;
  }

  if (loadFailed || inventory === null || endpoint === null) {
    return (
      <PageFailure
        eyebrow="Inventory"
        title="Inventory is temporarily unavailable"
        body="No sections are shown because none could be read. This is not evidence that the device has reported nothing. Nothing was changed."
      >
        <Link href={`/endpoints/${encodeURIComponent(endpointId)}/inventory`}>Try again</Link>
        <Link href={`/endpoints/${encodeURIComponent(endpointId)}`}>Back to the device</Link>
      </PageFailure>
    );
  }

  // A section that could not be collected must not sit quietly beside a healthy
  // one — an unread BitLocker state is the case this page exists to surface.
  const attention = inventory.sections.filter(
    (section) => statusTone(section.status) === "failed",
  );
  const latest = inventory.sections.reduce<string | null>(
    (newest, section) => (newest === null || Date.parse(section.collected_at) > Date.parse(newest) ? section.collected_at : newest),
    null,
  );
  // This server-only request timestamp is serialized into the client component
  // as a boolean, so hydration never recomputes or disagrees about freshness.
  // eslint-disable-next-line react-hooks/purity
  const renderedAt = Date.now();
  const canDispatch = session.operator.role === "operator" || session.operator.role === "admin";

  return (
    <PageStack>
      <EndpointSectionHeader
        endpointId={endpointId}
        hostname={endpoint.hostname}
        section="inventory"
        description="What this device reported, when it reported it, and how completely. A section is stored only when its content changes, so each time shown is the last time the value actually differed."
      />

      <StatRow>
        <StatTile icon={Layers} label="Sections reported" value={inventory.sections.length} tone="info" />
        <StatTile
          icon={CircleAlert}
          label="Could not be read"
          value={attention.length}
          sub={attention.length ? "Unread is not the same as fine" : "No collection failures reported"}
          tone={attention.length ? "crit" : "off"}
        />
        <StatTile icon={ListX} label="Never reported" value={inventory.missing_sections.length} tone={inventory.missing_sections.length ? "warn" : "off"} />
        <StatTile icon={Clock} label="Latest collection" value={<span className="text-base">{latest ? formatEndpointDateTime(latest) : "None yet"}</span>} tone="off" />
      </StatRow>

      {attention.length > 0 ? (
        <Notice tone="crit" role="alert" title={`${attention.length} section${attention.length === 1 ? "" : "s"} could not be read`}>
          {attention.map((section) => sectionLabel(section.section)).join(", ")}. These sections could not be collected; their configuration is unknown.
        </Notice>
      ) : null}

      {inventory.sections.length === 0 ? (
        <div className={cardClass}>
          <EmptyState
            icon={HardDrive}
            title="This device has not reported inventory yet"
            body="No inventory is available yet. Collection may still be pending."
          />
        </div>
      ) : (
        <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,420px),1fr))] items-start gap-6">
          {inventory.sections.map((section) => {
            if (section.section === "windows_updates") {
              const view = windowsUpdatesFromUnknown(section.payload);
              if (view) {
                return (
                  <div className="col-span-full min-w-0" key={section.id}>
                    <WindowsUpdateInstallation
                      canDispatch={canDispatch}
                      endpointId={endpointId}
                      hostname={endpoint.hostname}
                      isStale={windowsUpdateScanIsStale(view.scanned_at, renderedAt)}
                      sectionStatus={section.status}
                      trusted={endpoint.trust_state === "active"}
                      view={view}
                    />
                  </div>
                );
              }
            }
            return <InventorySectionCard endpointId={endpointId} key={section.id} section={section} />;
          })}
        </div>
      )}

      {inventory.missing_sections.length > 0 ? (
        <Panel
          title={`Never reported: ${inventory.missing_sections.length} section${inventory.missing_sections.length === 1 ? "" : "s"}`}
        >
          <p className="m-0 px-5 py-4 text-sm text-(--slate)">
            {inventory.missing_sections.map(sectionLabel).join(", ")}. These are named rather than hidden so a gap in coverage is visible instead of looking like the section does not exist.
          </p>
        </Panel>
      ) : null}
    </PageStack>
  );
}

