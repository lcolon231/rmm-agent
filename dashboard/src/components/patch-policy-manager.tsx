// SPDX-License-Identifier: AGPL-3.0-only
"use client";

import { CalendarClock, CircleAlert, Layers3, ListChecks, Plus, ShieldCheck, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useMemo, useState, type ReactNode } from "react";

import { PATCH_POLICIES_DESCRIPTION } from "@/components/patching/copy";
import { PageHeader, PageStack } from "@/components/shell/page-header";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { cx, focusRing } from "@/components/ui/cx";
import { DataTable, PrimaryCell, TableFooter, type Column } from "@/components/ui/data-table";
import { DefinitionList, Drawer } from "@/components/ui/drawer";
import { Input, Select } from "@/components/ui/field";
import { FilterBar, FilterChip } from "@/components/ui/filter-bar";
import { StatRow, StatTile } from "@/components/ui/stat-tile";
import { EmptyState } from "@/components/ui/states";
import { StatusBadge } from "@/components/ui/status-badge";
import { formatDurationSeconds } from "@/lib/maintenance-windows-core";
import { formatMonitoringTimestamp } from "@/lib/monitoring-core";
import {
  formatPatchScope,
  type PatchApprovalPolicy,
  type PatchDefaultAction,
  type PatchScope,
  type RebootPolicy,
} from "@/lib/patch-policies-core";

const scopeOptions: Array<{ value: PatchScope; label: string }> = [
  { value: "global", label: "Global (all managed endpoints)" },
  { value: "client", label: "Client" },
  { value: "site", label: "Site" },
  { value: "agent", label: "Endpoint" },
];

const REBOOT_LABEL: Record<RebootPolicy, string> = { never: "Never", if_required: "If required", forced: "Forced" };

type StateFilter = "all" | "active" | "disabled";

function byName(a: PatchApprovalPolicy, b: PatchApprovalPolicy) {
  return a.name.localeCompare(b.name);
}

function appliesTo(policy: PatchApprovalPolicy): ReactNode {
  return (
    <PrimaryCell
      title={formatPatchScope(policy.scope)}
      sub={policy.scope_id ? <span className="font-(family-name:--font-data)">{policy.scope_id}</span> : "All managed endpoints"}
    />
  );
}

function stateBadge(policy: PatchApprovalPolicy) {
  return policy.enabled ? <StatusBadge tone="ok">Active</StatusBadge> : <StatusBadge tone="off">Disabled</StatusBadge>;
}

function Checkbox({ checked, onChange, children }: { checked: boolean; onChange: (value: boolean) => void; children: string }) {
  return (
    <label className="flex items-center gap-2.5 text-sm text-(--slate)">
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} className={cx("size-4 accent-(--primary-strong)", focusRing)} />
      <span>{children}</span>
    </label>
  );
}

export function PatchPolicyManager({
  initialPolicies,
  canAdmin,
}: {
  initialPolicies: PatchApprovalPolicy[];
  canAdmin: boolean;
}) {
  const router = useRouter();
  const [policies, setPolicies] = useState(initialPolicies);
  const [name, setName] = useState("");
  const [scope, setScope] = useState<PatchScope>("global");
  const [scopeId, setScopeId] = useState("");
  const [defaultAction, setDefaultAction] = useState<PatchDefaultAction>("deny");
  const [requireWindow, setRequireWindow] = useState(false);
  const [rebootPolicy, setRebootPolicy] = useState<RebootPolicy>("never");
  const [rebootDelay, setRebootDelay] = useState(300);
  const [rebootRequiresNoUser, setRebootRequiresNoUser] = useState(true);
  const [maxAttempts, setMaxAttempts] = useState(2);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [createError, setCreateError] = useState("");
  const [deleteError, setDeleteError] = useState("");
  const [creating, setCreating] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<PatchApprovalPolicy | null>(null);
  const [filter, setFilter] = useState<StateFilter>("all");

  const ordered = useMemo(() => [...policies].sort(byName), [policies]);
  const activeCount = policies.filter((policy) => policy.enabled).length;
  const shown = ordered.filter((policy) => filter === "all" || (filter === "active") === policy.enabled);
  const selected = policies.find((policy) => policy.id === selectedId) ?? null;

  async function responseBody<T>(response: Response): Promise<T> {
    const body = await response.json().catch(() => null) as (T & { error?: string }) | null;
    if (!response.ok || !body) throw new Error(body?.error ?? "The change could not be confirmed.");
    return body;
  }

  async function create(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("create");
    setCreateError("");
    try {
      const response = await fetch("/api/patch-policies", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name,
          scope,
          scope_id: scope === "global" ? null : scopeId.trim(),
          enabled: true,
          rules: [],
          default_action: defaultAction,
          require_maintenance_window: requireWindow,
          reboot_policy: rebootPolicy,
          reboot_delay_seconds: rebootDelay,
          reboot_requires_no_user: rebootRequiresNoUser,
          max_install_attempts: maxAttempts,
        }),
      });
      const body = await responseBody<{ policy: PatchApprovalPolicy }>(response);
      setPolicies((current) => [...current, body.policy].sort(byName));
      setName("");
      setScopeId("");
      setCreating(false);
      router.refresh();
    } catch (caught) {
      setCreateError(caught instanceof Error ? caught.message : "The policy could not be created.");
    } finally {
      setBusy(null);
    }
  }

  async function toggle(policy: PatchApprovalPolicy) {
    setBusy(`toggle:${policy.id}`);
    setError("");
    try {
      const response = await fetch(`/api/patch-policies/${encodeURIComponent(policy.id)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !policy.enabled }),
      });
      const body = await responseBody<{ policy: PatchApprovalPolicy }>(response);
      setPolicies((current) => current.map((item) => (item.id === policy.id ? body.policy : item)));
      router.refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The policy could not be updated.");
    } finally {
      setBusy(null);
    }
  }

  // The delete API takes no reason, so the typed reason is a deliberate pause
  // and is not sent; the deletion itself is recorded by the management service.
  async function remove(policy: PatchApprovalPolicy) {
    setBusy(`delete:${policy.id}`);
    setDeleteError("");
    try {
      const response = await fetch(`/api/patch-policies/${encodeURIComponent(policy.id)}`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
      });
      await responseBody<{ deleted: true }>(response);
      setPolicies((current) => current.filter((item) => item.id !== policy.id));
      setDeleting(null);
      router.refresh();
    } catch (caught) {
      setDeleteError(`${caught instanceof Error ? caught.message : "The policy could not be deleted."} Nothing was changed.`);
    } finally {
      setBusy(null);
    }
  }

  function openCreate() {
    setCreateError("");
    setSelectedId(null);
    setCreating(true);
  }

  function openDelete(policy: PatchApprovalPolicy) {
    setDeleteError("");
    setSelectedId(null);
    setDeleting(policy);
  }

  const columns: Column<PatchApprovalPolicy>[] = [
    { key: "policy", header: "Policy", cell: (policy) => <PrimaryCell title={policy.name} sub={`Version ${policy.current_version}`} /> },
    { key: "scope", header: "Applies to", cell: appliesTo },
    { key: "default", header: "Unmatched updates", cell: (policy) => (policy.default_action === "approve" ? "Approved" : "Denied") },
    { key: "installs", header: "Installs during", cell: (policy) => (policy.require_maintenance_window ? "Maintenance windows only" : "Any time") },
    { key: "restart", header: "Restart", cell: (policy) => REBOOT_LABEL[policy.reboot_policy] },
    { key: "rules", header: "Rules", align: "end", cell: (policy) => <span className="tabular-nums">{policy.rule_count}</span> },
    { key: "state", header: "State", cell: stateBadge },
  ];

  const tableState =
    policies.length === 0 ? (
      <EmptyState
        icon={ShieldCheck}
        title="No patch approval policies yet"
        body={canAdmin ? "Create a policy so the devices it covers stop being exempt." : "Until a policy is created, Windows Update installs proceed without an approval gate."}
        actionLabel={canAdmin ? "New policy" : undefined}
        onAction={canAdmin ? openCreate : undefined}
      />
    ) : shown.length === 0 ? (
      <EmptyState title="No policies match" body="Clear the filter to see every policy." actionLabel="Clear filters" onAction={() => setFilter("all")} />
    ) : undefined;

  return (
    <PageStack>
      <PageHeader
        breadcrumb={[{ label: "Patching" }, { label: "Patch policies" }]}
        title="Patch policies"
        description={PATCH_POLICIES_DESCRIPTION}
        actions={canAdmin ? <Button variant="primary" icon={Plus} onClick={openCreate}>New policy</Button> : null}
      />
      <StatRow>
        <StatTile icon={ShieldCheck} label="Policies" value={policies.length} sub={`${activeCount} active · ${policies.length - activeCount} disabled`} />
        <StatTile
          icon={ListChecks}
          label="Approve by default"
          value={policies.filter((policy) => policy.default_action === "approve").length}
          sub="Unmatched updates are approved"
        />
        <StatTile
          icon={CalendarClock}
          label="Need a window"
          value={policies.filter((policy) => policy.require_maintenance_window).length}
          sub="Install only in a maintenance window"
        />
        <StatTile icon={Layers3} label="Specific rules" value={policies.reduce((sum, policy) => sum + policy.rule_count, 0)} sub="Across all policies" />
      </StatRow>
      <p className="m-0 flex items-start gap-2 text-[13px] text-(--muted)">
        <Layers3 size={16} aria-hidden="true" className="mt-0.5 shrink-0" />
        The most specific policy that targets a device governs its installs. Updates no rule matches get the policy default. With no policy, installs proceed unchanged.
      </p>
      {canAdmin ? null : (
        <p role="status" className="m-0 text-sm text-(--muted)">
          Your role can review patch policies. Creating, enabling, disabling or deleting one needs the administrator role.
        </p>
      )}
      {error && !selected ? (
        <p role="alert" className="m-0 flex items-center gap-2 rounded-lg bg-(--red-soft) px-4 py-3 text-sm text-(--red)">
          <CircleAlert size={16} aria-hidden="true" />
          {error} Nothing was changed.
        </p>
      ) : null}
      <DataTable
        caption="Patch policies"
        columns={columns}
        rows={shown}
        rowKey={(policy) => policy.id}
        rowLabel={(policy) => `Show rules for ${policy.name}`}
        onRowSelect={(policy) => setSelectedId(policy.id)}
        state={tableState}
        minWidth={960}
        filters={
          <FilterBar>
            <div role="group" aria-label="Filter by state" className="flex flex-wrap gap-2">
              <FilterChip selected={filter === "all"} count={policies.length} onClick={() => setFilter("all")}>All</FilterChip>
              <FilterChip selected={filter === "active"} count={activeCount} onClick={() => setFilter("active")}>Active</FilterChip>
              <FilterChip selected={filter === "disabled"} count={policies.length - activeCount} onClick={() => setFilter("disabled")}>Disabled</FilterChip>
            </div>
          </FilterBar>
        }
        footer={shown.length > 0 ? <TableFooter shown={shown.length} total={policies.length} sortNote="by name" /> : null}
      />

      {selected ? (
        <Drawer
          open
          onClose={() => setSelectedId(null)}
          context={formatPatchScope(selected.scope)}
          title={selected.name}
          sub={selected.scope_id ? <span className="font-(family-name:--font-data)">{selected.scope_id}</span> : "All managed endpoints"}
          record={`Version ${selected.current_version} · first created ${formatMonitoringTimestamp(selected.created_at)}. Each change is kept as a new version.`}
          footer={
            canAdmin ? (
              <>
                <Button onClick={() => toggle(selected)} disabled={Boolean(busy)}>
                  {selected.enabled ? "Disable policy" : "Enable policy"}
                </Button>
                <Button variant="danger" icon={Trash2} onClick={() => openDelete(selected)} disabled={Boolean(busy)}>
                  Delete policy
                </Button>
              </>
            ) : null
          }
        >
          <div className="flex items-center gap-2">{stateBadge(selected)}</div>
          <section className="grid gap-2.5">
            <h3 className="m-0 text-sm font-semibold text-(--ink)">Rules</h3>
            <DefinitionList
              items={[
                { term: "Unmatched updates", value: selected.default_action === "approve" ? "Approved" : "Denied" },
                {
                  term: "Specific rules",
                  value: selected.rule_count === 0 ? "None. The default applies to every update." : `${selected.rule_count}`,
                },
                { term: "Installs during", value: selected.require_maintenance_window ? "Maintenance windows only" : "Any time" },
              ]}
            />
          </section>
          <section className="grid gap-2.5">
            <h3 className="m-0 text-sm font-semibold text-(--ink)">Installation and restart</h3>
            <DefinitionList
              items={[
                { term: "Restart", value: REBOOT_LABEL[selected.reboot_policy] },
                { term: "Restart delay", value: formatDurationSeconds(selected.reboot_delay_seconds) },
                { term: "Only when nobody is signed in", value: selected.reboot_requires_no_user ? "Yes" : "No" },
                { term: "Install attempts", value: `Up to ${selected.max_install_attempts}` },
                { term: "Policy ID", value: <span className="font-(family-name:--font-data) text-[13px]">{selected.id}</span> },
              ]}
            />
          </section>
          {error ? <p role="alert" className="m-0 text-sm text-(--red)">{error} Nothing was changed.</p> : null}
        </Drawer>
      ) : null}

      {canAdmin && creating ? (
        <Drawer
          open
          onClose={() => setCreating(false)}
          title="New patch policy"
          sub="New policies apply the default action to every update and are enabled when created."
          footer={
            <>
              <Button type="submit" form="new-patch-policy" variant="primary" icon={Plus} disabled={busy === "create"} aria-busy={busy === "create" || undefined}>
                {busy === "create" ? "Creating…" : "Create policy"}
              </Button>
              <Button onClick={() => setCreating(false)}>Cancel</Button>
            </>
          }
        >
          <form id="new-patch-policy" className="grid gap-4" onSubmit={create}>
            <Input label="Policy name" value={name} onChange={(e) => setName(e.target.value)} maxLength={200} placeholder="e.g. Workstation baseline" required />
            <Select label="Scope" value={scope} onChange={(e) => setScope(e.target.value as PatchScope)}>
              {scopeOptions.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </Select>
            {scope !== "global" ? (
              <Input label={`${formatPatchScope(scope)} ID`} value={scopeId} onChange={(e) => setScopeId(e.target.value)} maxLength={36} placeholder="Target ID" required />
            ) : null}
            <Select label="Default action" value={defaultAction} onChange={(e) => setDefaultAction(e.target.value as PatchDefaultAction)}>
              <option value="deny">Deny unmatched updates</option>
              <option value="approve">Approve unmatched updates</option>
            </Select>
            <Checkbox checked={requireWindow} onChange={setRequireWindow}>Require an active maintenance window to install</Checkbox>
            <Select label="Reboot policy" value={rebootPolicy} onChange={(e) => setRebootPolicy(e.target.value as RebootPolicy)}>
              <option value="never">Never</option>
              <option value="if_required">If required</option>
              <option value="forced">Forced</option>
            </Select>
            <Input label="Reboot delay (seconds)" type="number" min={60} max={3600} value={rebootDelay} onChange={(e) => setRebootDelay(Number(e.target.value))} />
            <Input label="Max install attempts" type="number" min={1} max={5} value={maxAttempts} onChange={(e) => setMaxAttempts(Number(e.target.value))} />
            <Checkbox checked={rebootRequiresNoUser} onChange={setRebootRequiresNoUser}>Only reboot when no user is signed in</Checkbox>
            {createError ? (
              <p role="alert" className="m-0 flex items-center gap-2 text-sm text-(--red)">
                <CircleAlert size={16} aria-hidden="true" />
                {createError} Nothing was changed.
              </p>
            ) : null}
          </form>
        </Drawer>
      ) : null}

      <ConfirmDialog
        open={canAdmin && deleting !== null}
        onCancel={() => setDeleting(null)}
        onConfirm={() => (deleting ? remove(deleting) : undefined)}
        title={deleting ? `Delete ${deleting.name}?` : "Delete policy?"}
        consequence="Devices it governs fall back to a broader policy if one applies, otherwise they become exempt and their installs are no longer gated. This cannot be undone."
        confirmLabel="Delete policy"
        busy={deleting !== null && busy === `delete:${deleting.id}`}
        error={deleteError || undefined}
      />
    </PageStack>
  );
}
