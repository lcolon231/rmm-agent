// SPDX-License-Identifier: AGPL-3.0-only

import { CircleAlert, Clock, Info, ListChecks, Lock } from "lucide-react";
import Link from "next/link";

import { CommandAutoRefresh } from "@/components/command-auto-refresh";
import { CommandDispatchForm } from "@/components/command-dispatch-form";
import type { DashboardOperator } from "@/lib/dashboard-auth-core";
import type { EndpointDetailData } from "@/lib/endpoint-detail";
import { hasActiveCommands, type CommandHistoryData } from "@/lib/command-console-core";
import type { MaintenanceWindow } from "@/lib/maintenance-windows-core";

import { CommandHistoryTable } from "./endpoint/command-history-table";
import { EndpointSectionHeader, inlineLink, Notice, Panel } from "./endpoint/section-header";
import { PageStack } from "./shell/page-header";
import { StatRow, StatTile } from "./ui/stat-tile";

export function CommandConsoleView({
  endpoint,
  history,
  operator,
  maintenanceWindows,
  serverNowMs,
}: {
  endpoint: EndpointDetailData;
  history: CommandHistoryData;
  operator: DashboardOperator;
  /** Null when the window inventory could not be verified. */
  maintenanceWindows: MaintenanceWindow[] | null;
  serverNowMs: number;
}) {
  const canDispatch = operator.role === "operator" || operator.role === "admin";
  const canExecuteScripts = endpoint.script_execution_allowed;
  const trusted = endpoint.trust_state === "active";
  const queueFull = history.outstanding >= history.outstanding_limit;
  const failedOnPage = history.items.filter((item) => item.status === "failed").length;

  return (
    <PageStack>
      {hasActiveCommands(history.items) ? <CommandAutoRefresh /> : null}
      <EndpointSectionHeader
        endpointId={endpoint.id}
        hostname={endpoint.hostname}
        section="commands"
        description="Every command is signed, expires on schedule, and is written to the audit log with your operator identity."
      />

      <StatRow>
        <StatTile icon={ListChecks} label="All commands" value={history.total} sub="Sent to this device" />
        <StatTile
          icon={Clock}
          label="Waiting or running"
          value={history.outstanding}
          sub={queueFull ? `Queue full: limit ${history.outstanding_limit}` : `Queue limit ${history.outstanding_limit}`}
          tone={queueFull ? "warn" : "info"}
        />
        <StatTile
          icon={CircleAlert}
          label="Failed"
          value={failedOnPage}
          sub={`Of the ${history.items.length} shown on this page`}
          tone={failedOnPage > 0 ? "crit" : "off"}
        />
      </StatRow>

      {!trusted ? (
        <Notice tone="warn" icon={Lock} title={`Sending is blocked: this device is ${endpoint.trust_state}`}>
          Restore the device&apos;s trust before queueing new work. History stays available below.
        </Notice>
      ) : null}

      {!canDispatch ? (
        <Notice tone="off" icon={Info} title="Read-only access">
          Your role can review command history and results, but sending commands requires the operator role.
        </Notice>
      ) : null}

      {canDispatch && trusted ? (
        <Panel title="Send a command" sub="It is signed for this device only and stops at its expiry if the device never picks it up.">
          <div className="grid gap-4 px-5 py-5">
            {queueFull ? (
              <Notice tone="warn" title={`The queue is at its ${history.outstanding_limit}-command limit`}>
                New commands will be refused until waiting ones finish or expire.
              </Notice>
            ) : null}
            {!canExecuteScripts ? (
              <Notice tone="off" icon={Lock} title="Scripts are not allowed on this device">
                PowerShell and shell scripts are blocked by default. An administrator must grant your operator a matching scope. Inventory collection remains available.
              </Notice>
            ) : null}
            <p className="m-0 text-sm text-(--slate)">
              Windows updates are chosen from the device&apos;s latest scan, so a normal install can never mean &ldquo;install everything.&rdquo;{" "}
              <Link href={`/endpoints/${encodeURIComponent(endpoint.id)}/inventory#windows-updates`} className={inlineLink}>
                Select Windows updates
              </Link>
            </p>
            <CommandDispatchForm
              canExecuteScripts={canExecuteScripts}
              endpointId={endpoint.id}
              hostname={endpoint.hostname}
              isAdmin={operator.role === "admin"}
              maintenanceTarget={{
                agentId: endpoint.id,
                siteId: endpoint.site_id,
                clientId: endpoint.client_id,
              }}
              maintenanceWindows={maintenanceWindows}
              serverNowMs={serverNowMs}
            />
          </div>
        </Panel>
      ) : null}

      <CommandHistoryTable endpointId={endpoint.id} history={history} isAdmin={operator.role === "admin"} />

      <p className="m-0 text-xs text-(--muted)">
        Commands cannot be cancelled after they are sent; one the device never picks up stops at its signed expiry. Device ID{" "}
        <span className="font-(family-name:--font-data)">{endpoint.id}</span>
      </p>
    </PageStack>
  );
}
