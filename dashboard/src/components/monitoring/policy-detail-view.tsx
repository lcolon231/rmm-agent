// SPDX-License-Identifier: AGPL-3.0-only

import { formatMonitoringScope, formatMonitoringTimestamp, type MonitoringPolicyDetail } from "@/lib/monitoring-core";
import {
  checkTypeWord,
  intervalWords,
  paramsWords,
  policyStateWord,
  scopeLabel,
  thresholdWords,
  type PolicyTab,
} from "@/lib/monitoring-view-core";

import { PageHeader, PageStack } from "../shell/page-header";
import { DefinitionList } from "../ui/drawer";
import { EmptyState } from "../ui/states";
import { StatusBadge } from "../ui/status-badge";
import { TabNav } from "../ui/tab-nav";
import { Card } from "./detail-card";

function plural(count: number, word: string) {
  return `${count} ${word}${count === 1 ? "" : "s"}`;
}

function RuleTab({ policy }: { policy: MonitoringPolicyDetail }) {
  return (
    <Card title="What is checked" sub={`${plural(policy.checks.length, "check")} in revision ${policy.current_version}. A switched-off check removes the same check inherited from a broader policy.`}>
      {policy.checks.length === 0 ? (
        <EmptyState title="This revision has no checks" body="An empty policy adds no checks to the devices it covers." />
      ) : (
        <ul className="m-0 grid list-none p-0">
          {policy.checks.map((check) => (
            <li key={check.key} className="grid gap-3 border-t border-(--line) px-5 py-4 first:border-t-0">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="grid gap-0.5">
                  <h3 className="m-0 text-sm font-semibold text-(--ink)">{checkTypeWord(check.type)}</h3>
                  <span className="font-(family-name:--font-data) text-xs text-(--muted)">{check.key}</span>
                </div>
                {check.enabled ? <StatusBadge tone="ok">Active</StatusBadge> : <StatusBadge tone="off">Disabled</StatusBadge>}
              </div>
              <DefinitionList
                items={[
                  { term: "How often", value: intervalWords(check.schedule.interval_seconds) },
                  { term: "Limits", value: thresholdWords(check.threshold) },
                  {
                    term: "Raised after",
                    value: `${plural(check.hysteresis.raise_samples, "bad result")} in a row; clears after ${plural(check.hysteresis.clear_samples, "good result")}`,
                  },
                  { term: "Settings", value: paramsWords(check.params) },
                ]}
              />
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

function HistoryTab({ policy }: { policy: MonitoringPolicyDetail }) {
  return (
    <Card title="Change history" sub="Newest first. Earlier revisions are kept as they were.">
      {policy.revisions.length === 0 ? (
        <EmptyState title="No revisions returned" body="The server returned no revisions for this policy." />
      ) : (
        <ol className="m-0 grid list-none p-0">
          {policy.revisions.map((revision) => (
            <li key={revision.id} className="flex gap-3 border-t border-(--line) px-5 py-3.5 first:border-t-0">
              <span className="flex h-6 shrink-0 items-center rounded-full bg-(--fog) px-2 font-(family-name:--font-data) text-xs font-semibold text-(--slate)">
                v{revision.version}
              </span>
              <div className="grid min-w-0 flex-1 gap-0.5">
                <span className="font-semibold text-(--ink)">{plural(revision.checks.length, "check")}</span>
                <span className="text-[13px] break-words text-(--muted)">{revision.change_note || "No change note was given."}</span>
                {revision.created_by ? <span className="font-(family-name:--font-data) text-xs text-(--muted)">{revision.created_by}</span> : null}
              </div>
              <time className="shrink-0 text-xs text-(--muted)">{formatMonitoringTimestamp(revision.created_at)}</time>
            </li>
          ))}
        </ol>
      )}
    </Card>
  );
}

export function PolicyDetailView({ policy, tab }: { policy: MonitoringPolicyDetail; tab: PolicyTab }) {
  const base = `/monitoring/${encodeURIComponent(policy.id)}`;
  const state = policyStateWord(policy.enabled);
  const latest = policy.revisions[0];
  return (
    <PageStack>
      <PageHeader
        breadcrumb={[{ label: "Devices" }, { label: "Monitoring", href: "/monitoring" }, { label: policy.name }]}
        title={policy.name}
        status={<StatusBadge tone={state.tone}>{state.label}</StatusBadge>}
        description={`A set of checks NodeLink runs on ${scopeLabel(policy.scope, policy.scope_id).toLowerCase()}. Now at revision ${policy.current_version}.`}
      />
      <TabNav
        label="Policy sections"
        tabs={[
          { label: "Rule", href: base, current: tab === "rule" },
          { label: `Change history (${policy.revisions.length})`, href: `${base}?tab=history`, current: tab === "history" },
        ]}
      />
      <div className="grid items-start gap-6 min-[1100px]:grid-cols-[minmax(0,2fr)_minmax(280px,1fr)]">
        <div className="grid min-w-0 gap-6">{tab === "history" ? <HistoryTab policy={policy} /> : <RuleTab policy={policy} />}</div>
        <aside aria-label="Policy facts" className="grid min-w-0 gap-6">
          <Card title="At a glance">
            <div className="px-5 py-4 text-sm">
              <DefinitionList
                items={[
                  { term: "State", value: state.label },
                  { term: "Level", value: formatMonitoringScope(policy.scope) },
                  {
                    term: "Applies to",
                    value: policy.scope_id ? <span className="font-(family-name:--font-data)">{policy.scope_id}</span> : "Every managed device",
                  },
                  { term: "Checks", value: String(policy.check_count) },
                  { term: "Revision", value: `v${policy.current_version}` },
                  { term: "Created", value: formatMonitoringTimestamp(policy.created_at) },
                ]}
              />
            </div>
          </Card>
          <Card title="Record" sub="Who did what, and when">
            <ul className="m-0 grid list-none gap-2.5 px-5 py-4 text-[13px]">
              {latest ? (
                <li className="grid gap-0.5">
                  <span className="text-(--ink)">
                    Revision {latest.version} saved{latest.created_by ? <> by <span className="font-(family-name:--font-data)">{latest.created_by}</span></> : " (author not recorded)"}
                  </span>
                  <time className="text-xs text-(--muted)">{formatMonitoringTimestamp(latest.created_at)}</time>
                </li>
              ) : null}
              <li className="grid gap-0.5">
                <span className="text-(--ink)">Policy created</span>
                <time className="text-xs text-(--muted)">{formatMonitoringTimestamp(policy.created_at)}</time>
              </li>
            </ul>
          </Card>
        </aside>
      </div>
    </PageStack>
  );
}
