// SPDX-License-Identifier: AGPL-3.0-only
"use client";

import { Check, CircleCheck, CircleX, Clipboard, KeyRound, Pencil, Plus, RefreshCw, Trash2, Webhook, X } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";

import {
  formatMonitoringTimestamp,
  type WebhookDestinationValidation,
  type WebhookEndpoint,
  type WebhookEndpointSecret,
  type WebhookEventType,
  type WebhookStatus,
} from "@/lib/monitoring-core";
import { alertEventWord, policyStateWord } from "@/lib/monitoring-view-core";

import { MonitoringTabs } from "./monitoring/monitoring-tabs";
import { PageHeader, PageStack } from "./shell/page-header";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { cx } from "./ui/cx";
import { DataTable, PrimaryCell, TableFooter, type Column } from "./ui/data-table";
import { DefinitionList, Drawer } from "./ui/drawer";
import { Input } from "./ui/field";
import { StatRow, StatTile } from "./ui/stat-tile";
import { EmptyState } from "./ui/states";
import { StatusBadge, toneStyles } from "./ui/status-badge";

const EVENT_TYPES: WebhookEventType[] = [
  "opened",
  "reopened",
  "acknowledged",
  "manual_resolution",
  "automatic_recovery",
  "policy_revised",
  "policy_deleted",
  "policy_superseded",
];

const defaultEvents: WebhookEventType[] = ["opened", "reopened", "acknowledged", "manual_resolution", "automatic_recovery"];

function requestId() {
  return crypto.randomUUID().replaceAll("-", "");
}

function publicEndpoint(endpoint: WebhookEndpointSecret): WebhookEndpoint {
  return {
    id: endpoint.id,
    name: endpoint.name,
    url: endpoint.url,
    event_types: endpoint.event_types,
    enabled: endpoint.enabled,
    current_secret_version: endpoint.current_secret_version,
    current_secret_key_id: endpoint.current_secret_key_id,
    version: endpoint.version,
    deleted_at: endpoint.deleted_at,
    created_at: endpoint.created_at,
    updated_at: endpoint.updated_at,
  };
}

function validationWords(validation: WebhookDestinationValidation): { tone: "ok" | "crit" | "off"; text: string } {
  const code = validation.code ? ` · ${validation.code.replaceAll("_", " ")}` : "";
  if (validation.state === "valid") {
    const count = validation.resolved_address_count;
    return { tone: "ok", text: `Address check passed · ${count} public ${count === 1 ? "address" : "addresses"}${code}` };
  }
  if (validation.state === "invalid") return { tone: "crit", text: `Address check failed${code}` };
  if (validation.state === "unsupported") return { tone: "off", text: `This address cannot be used${code}` };
  return { tone: "off", text: `The address could not be checked right now${code}` };
}

function EventChoices({ legend, selected, onToggle, disabled }: { legend: string; selected: WebhookEventType[]; onToggle: (value: WebhookEventType) => void; disabled?: boolean }) {
  return (
    <fieldset className="m-0 grid gap-2 border-0 p-0" disabled={disabled}>
      <legend className="mb-1.5 p-0 text-[13px] font-semibold text-(--slate)">{legend}</legend>
      {EVENT_TYPES.map((value) => (
        <label key={value} className="flex items-center gap-2 text-sm text-(--ink)">
          <input type="checkbox" className="size-4 accent-(--primary-strong)" checked={selected.includes(value)} onChange={() => onToggle(value)} />
          <span>{alertEventWord(value)}</span>
        </label>
      ))}
      {selected.length === 0 ? <p className="m-0 text-xs text-[#89500b]">Choose at least one change to send.</p> : null}
    </fieldset>
  );
}

function toggled(value: WebhookEventType, selected: WebhookEventType[]) {
  return selected.includes(value) ? selected.filter((item) => item !== value) : [...selected, value];
}

type Pending = { kind: "rotate" | "remove"; endpoint: WebhookEndpoint };

export function WebhookEndpointManager({
  initialEndpoints,
  status,
  canAdmin,
  canOperate,
}: {
  initialEndpoints: WebhookEndpoint[];
  status: WebhookStatus;
  canAdmin: boolean;
  canOperate: boolean;
}) {
  const router = useRouter();
  const [endpoints, setEndpoints] = useState(initialEndpoints);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [events, setEvents] = useState<WebhookEventType[]>(defaultEvents);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [secretReveal, setSecretReveal] = useState<WebhookEndpointSecret | null>(null);
  const [copied, setCopied] = useState(false);
  const [validations, setValidations] = useState<Record<string, WebhookDestinationValidation>>({});
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [editName, setEditName] = useState("");
  const [editUrl, setEditUrl] = useState("");
  const [editEvents, setEditEvents] = useState<WebhookEventType[]>([]);
  const [pending, setPending] = useState<Pending | null>(null);
  const [pendingError, setPendingError] = useState("");

  const selected = endpoints.find((item) => item.id === selectedId) ?? null;

  async function responseBody<T>(response: Response): Promise<T> {
    const body = (await response.json().catch(() => null)) as (T & { error?: string }) | null;
    if (!response.ok || !body) throw new Error(body?.error ?? "The change could not be confirmed.");
    return body;
  }

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("create");
    setError("");
    try {
      const response = await fetch("/api/webhook-endpoints", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, url, event_types: events }),
      });
      const body = await responseBody<{ endpoint: WebhookEndpointSecret }>(response);
      const endpoint = publicEndpoint(body.endpoint);
      setEndpoints((current) => [...current, endpoint].sort((a, b) => a.name.localeCompare(b.name)));
      setSecretReveal(body.endpoint);
      setName("");
      setUrl("");
      setEvents(defaultEvents);
      setCopied(false);
      setCreating(false);
      router.refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The endpoint could not be created.");
    } finally {
      setBusy(null);
    }
  }

  async function validate(endpoint: WebhookEndpoint) {
    setBusy(`validate:${endpoint.id}`);
    setError("");
    try {
      const response = await fetch(`/api/webhook-endpoints/${encodeURIComponent(endpoint.id)}/validate`, { method: "POST" });
      const body = await responseBody<{ validation: WebhookDestinationValidation }>(response);
      setValidations((current) => ({ ...current, [endpoint.id]: body.validation }));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Validation could not be completed.");
    } finally {
      setBusy(null);
    }
  }

  async function update(endpoint: WebhookEndpoint, change: Partial<Pick<WebhookEndpoint, "name" | "enabled" | "event_types">> & { url?: string }) {
    setBusy(`update:${endpoint.id}`);
    setError("");
    try {
      const response = await fetch(`/api/webhook-endpoints/${encodeURIComponent(endpoint.id)}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ request_id: requestId(), expected_version: endpoint.version, ...change }),
      });
      const body = await responseBody<{ endpoint: WebhookEndpoint }>(response);
      setEndpoints((current) => current.map((item) => (item.id === endpoint.id ? body.endpoint : item)));
      setEditing(false);
      router.refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The endpoint could not be updated.");
    } finally {
      setBusy(null);
    }
  }

  async function rotate(endpoint: WebhookEndpoint) {
    setBusy(`rotate:${endpoint.id}`);
    setPendingError("");
    try {
      const response = await fetch(`/api/webhook-endpoints/${encodeURIComponent(endpoint.id)}/rotate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ request_id: requestId(), expected_version: endpoint.version }),
      });
      const body = await responseBody<{ endpoint: WebhookEndpointSecret }>(response);
      const rotatedEndpoint = publicEndpoint(body.endpoint);
      setEndpoints((current) => current.map((item) => (item.id === endpoint.id ? rotatedEndpoint : item)));
      setSecretReveal(body.endpoint);
      setCopied(false);
      setPending(null);
      router.refresh();
    } catch (caught) {
      setPendingError(caught instanceof Error ? caught.message : "The secret could not be rotated.");
    } finally {
      setBusy(null);
    }
  }

  async function remove(endpoint: WebhookEndpoint) {
    setBusy(`delete:${endpoint.id}`);
    setPendingError("");
    try {
      const response = await fetch(`/api/webhook-endpoints/${encodeURIComponent(endpoint.id)}`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ request_id: requestId(), expected_version: endpoint.version }),
      });
      await responseBody<{ deleted: true }>(response);
      setEndpoints((current) => current.filter((item) => item.id !== endpoint.id));
      setPending(null);
      router.refresh();
    } catch (caught) {
      setPendingError(caught instanceof Error ? caught.message : "The endpoint could not be removed.");
    } finally {
      setBusy(null);
    }
  }

  function openEndpoint(endpoint: WebhookEndpoint) {
    setSelectedId(endpoint.id);
    setEditing(false);
  }

  function beginEdit(endpoint: WebhookEndpoint) {
    setEditing(true);
    setEditName(endpoint.name);
    setEditUrl("");
    setEditEvents(endpoint.event_types);
  }

  /** The confirmation replaces the drawer so only one dialog is open at a time. */
  function askFirst(kind: Pending["kind"], endpoint: WebhookEndpoint) {
    setSelectedId(null);
    setEditing(false);
    setPendingError("");
    setPending({ kind, endpoint });
  }

  async function copySecret() {
    if (!secretReveal) return;
    await navigator.clipboard.writeText(secretReveal.secret);
    setCopied(true);
  }

  const enabledCount = endpoints.filter((item) => item.enabled).length;
  const delivered = status.counts.delivered;
  const failed = status.counts.failed;

  const columns: Column<WebhookEndpoint>[] = [
    {
      key: "destination",
      header: "Destination",
      cell: (endpoint) => <PrimaryCell title={endpoint.name} sub={<span className="font-(family-name:--font-data)">{endpoint.url}</span>} />,
    },
    { key: "events", header: "Sends", cell: (endpoint) => `${endpoint.event_types.length} of ${EVENT_TYPES.length} kinds of change` },
    {
      key: "key",
      header: "Signing key",
      cell: (endpoint) => (
        <span className="font-(family-name:--font-data) text-[13px]">
          v{endpoint.current_secret_version} · {endpoint.current_secret_key_id.slice(0, 8)}…
        </span>
      ),
    },
    { key: "updated", header: "Updated", cell: (endpoint) => formatMonitoringTimestamp(endpoint.updated_at) },
    {
      key: "state",
      header: "State",
      cell: (endpoint) => {
        const word = policyStateWord(endpoint.enabled);
        return <StatusBadge tone={word.tone}>{word.label}</StatusBadge>;
      },
    },
  ];

  const tableState =
    endpoints.length === 0 ? (
      <EmptyState
        icon={Webhook}
        title="No webhook destinations"
        body={canAdmin ? "Add the first destination to send signed alert changes to another system." : "An administrator has not set up a destination yet."}
      />
    ) : undefined;

  return (
    <PageStack>
      <PageHeader
        breadcrumb={[{ label: "Devices" }, { label: "Monitoring", href: "/monitoring" }, { label: "Webhook destinations" }]}
        title="Webhook destinations"
        description="Other systems NodeLink tells when an alert changes. Each delivery is signed so the receiver can check it came from NodeLink."
        actions={
          canAdmin ? (
            <Button variant="primary" icon={Plus} onClick={() => setCreating(true)} disabled={!status.encryption_key_configured}>
              Add a webhook
            </Button>
          ) : null
        }
      />
      <StatRow>
        <StatTile icon={Webhook} label="Destinations" value={endpoints.length} sub={`Up to ${status.endpoint_limit} allowed`} />
        <StatTile icon={CircleCheck} label="Active" tone={enabledCount ? "ok" : "off"} value={enabledCount} sub={`${endpoints.length - enabledCount} disabled`} />
        <StatTile icon={Check} label="Delivered" tone="ok" value={delivered ?? "—"} sub="All deliveries so far" />
        <StatTile icon={CircleX} label="Failed" tone={failed === undefined ? "off" : failed ? "crit" : "ok"} value={failed ?? "—"} sub="All deliveries so far" />
      </StatRow>
      <MonitoringTabs current="webhooks" />

      {!status.encryption_key_configured ? (
        <div role="alert" className={cx("flex items-start gap-3 rounded-lg px-4 py-3", toneStyles.warn.surface)}>
          <KeyRound size={18} aria-hidden="true" className={cx("mt-0.5 shrink-0", toneStyles.warn.text)} />
          <p className="m-0 grid gap-0.5 text-sm">
            <span className={cx("font-semibold", toneStyles.warn.text)}>Signing secrets cannot be stored yet</span>
            <span className="text-(--slate)">
              Set <span className="font-(family-name:--font-data)">WEBHOOK_SECRET_ENCRYPTION_KEY</span> on the server before adding a destination or rotating a secret.
            </span>
          </p>
        </div>
      ) : null}

      {secretReveal ? (
        <section role="status" aria-label="New signing secret" className={cx("grid gap-3 rounded-lg px-4 py-4", toneStyles.warn.surface)}>
          <div className="grid gap-0.5 text-sm">
            <span className={cx("font-semibold", toneStyles.warn.text)}>Copy the signing secret for {secretReveal.name} now</span>
            <span className="text-(--slate)">Store it in the receiving system. NodeLink keeps only an encrypted copy and will not show it again.</span>
          </div>
          <code className="block overflow-x-auto rounded-lg bg-(--ink-deep) p-3 font-(family-name:--font-data) text-[13px] break-all text-(--chrome-text)">{secretReveal.secret}</code>
          <div className="flex flex-wrap gap-2">
            <Button size="compact" icon={copied ? Check : Clipboard} onClick={() => void copySecret()}>
              {copied ? "Copied" : "Copy secret"}
            </Button>
            <Button size="compact" variant="quiet" icon={X} onClick={() => setSecretReveal(null)}>
              Dismiss
            </Button>
          </div>
        </section>
      ) : null}

      {error ? (
        <p role="alert" className="m-0 text-sm text-(--red)">
          {error}
        </p>
      ) : null}

      <DataTable
        caption="Webhook destinations"
        columns={columns}
        rows={endpoints}
        rowKey={(endpoint) => endpoint.id}
        rowLabel={(endpoint) => `Open ${endpoint.name}`}
        onRowSelect={openEndpoint}
        state={tableState}
        minWidth={820}
        footer={endpoints.length ? <TableFooter shown={endpoints.length} total={endpoints.length} sortNote="by name" /> : null}
      />
      <p className="m-0 text-[13px] text-(--muted)">
        Deliveries go only to public HTTPS addresses and are signed with HMAC-SHA256 in the <span className="font-(family-name:--font-data)">X-NodeLink-Signature</span> header. Saved addresses are
        shown masked; paths, query values and secrets are never sent back to the dashboard. Each alert page lists the webhooks sent for it.
      </p>

      {selected ? (
        <Drawer
          open
          onClose={() => {
            setSelectedId(null);
            setEditing(false);
          }}
          context="Webhook destination"
          title={selected.name}
          sub={<span className="font-(family-name:--font-data)">{selected.url}</span>}
          record={`Added ${formatMonitoringTimestamp(selected.created_at)} · last changed ${formatMonitoringTimestamp(selected.updated_at)}`}
          footer={
            canOperate ? (
              <Button icon={RefreshCw} onClick={() => void validate(selected)} disabled={Boolean(busy)}>
                {busy === `validate:${selected.id}` ? "Checking…" : "Check address"}
              </Button>
            ) : null
          }
        >
          <DefinitionList
            items={[
              { term: "State", value: <StatusBadge tone={policyStateWord(selected.enabled).tone}>{policyStateWord(selected.enabled).label}</StatusBadge> },
              { term: "Sends", value: selected.event_types.map((item) => alertEventWord(item)).join(" · ") },
              {
                term: "Signing key",
                value: (
                  <span className="font-(family-name:--font-data) text-[13px]">
                    v{selected.current_secret_version} · {selected.current_secret_key_id.slice(0, 8)}…
                  </span>
                ),
              },
              ...(validations[selected.id]
                ? [
                    {
                      term: "Address check",
                      value: (() => {
                        const words = validationWords(validations[selected.id]);
                        return <span className={toneStyles[words.tone].text}>{words.text}</span>;
                      })(),
                    },
                  ]
                : []),
            ]}
          />
          {canAdmin && editing ? (
            <form
              aria-label="Edit destination"
              className="grid gap-4"
              onSubmit={(event) => {
                event.preventDefault();
                void update(selected, { name: editName, event_types: editEvents, ...(editUrl.trim() ? { url: editUrl.trim() } : {}) });
              }}
            >
              <Input label="Name" value={editName} onChange={(event) => setEditName(event.target.value)} required />
              <Input
                label="Replace address"
                hint="Leave blank to keep the current address."
                value={editUrl}
                onChange={(event) => setEditUrl(event.target.value)}
                placeholder="https://new.example.com/nodelink"
              />
              <EventChoices legend="Changes to send" selected={editEvents} onToggle={(value) => setEditEvents((current) => toggled(value, current))} />
              <div className="flex flex-wrap gap-2">
                <Button type="submit" variant="primary" disabled={editEvents.length === 0 || busy === `update:${selected.id}`}>
                  {busy === `update:${selected.id}` ? "Saving…" : "Save changes"}
                </Button>
                <Button onClick={() => setEditing(false)}>Cancel</Button>
              </div>
            </form>
          ) : null}
          {canAdmin && !editing ? (
            <div className="grid gap-2">
              <h3 className="m-0 text-sm font-semibold text-(--ink)">Manage</h3>
              <div className="flex flex-wrap gap-2">
                <Button size="compact" icon={Pencil} onClick={() => beginEdit(selected)} disabled={Boolean(busy)}>
                  Edit
                </Button>
                <Button size="compact" onClick={() => void update(selected, { enabled: !selected.enabled })} disabled={Boolean(busy)}>
                  {selected.enabled ? "Disable" : "Enable"}
                </Button>
                <Button size="compact" variant="danger" icon={KeyRound} onClick={() => askFirst("rotate", selected)} disabled={Boolean(busy)}>
                  Rotate secret
                </Button>
                <Button size="compact" variant="danger" icon={Trash2} onClick={() => askFirst("remove", selected)} disabled={Boolean(busy)}>
                  Remove
                </Button>
              </div>
            </div>
          ) : null}
          {error ? (
            <p role="alert" className="m-0 text-sm text-(--red)">
              {error}
            </p>
          ) : null}
        </Drawer>
      ) : null}

      {canAdmin && creating ? (
        <Drawer open onClose={() => setCreating(false)} context="Webhook destinations" title="Add a webhook" sub="The address is looked up and checked before any secret is created.">
          <form aria-label="Add a webhook" className="grid gap-4" onSubmit={create}>
            <Input label="Name" value={name} onChange={(event) => setName(event.target.value)} maxLength={200} placeholder="Main incident relay" required />
            <Input
              label="Public HTTPS address"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              maxLength={2048}
              placeholder="https://hooks.example.com/nodelink"
              inputMode="url"
              required
            />
            <EventChoices legend="Changes to send" selected={events} onToggle={(value) => setEvents((current) => toggled(value, current))} />
            <div className="flex flex-wrap gap-2">
              <Button type="submit" variant="primary" icon={Webhook} disabled={busy === "create" || events.length === 0 || !status.encryption_key_configured}>
                {busy === "create" ? "Adding…" : "Add destination"}
              </Button>
              <Button onClick={() => setCreating(false)}>Cancel</Button>
            </div>
            {error ? (
              <p role="alert" className="m-0 text-sm text-(--red)">
                {error}
              </p>
            ) : null}
          </form>
        </Drawer>
      ) : null}

      <ConfirmDialog
        open={canAdmin && pending !== null}
        onCancel={() => setPending(null)}
        onConfirm={() => {
          if (!pending) return;
          return pending.kind === "rotate" ? rotate(pending.endpoint) : remove(pending.endpoint);
        }}
        title={pending?.kind === "remove" ? `Remove ${pending.endpoint.name}?` : `Rotate the signing secret for ${pending?.endpoint.name ?? "this destination"}?`}
        consequence={
          pending?.kind === "remove"
            ? "NodeLink stops sending alert changes to this destination. Its past deliveries stay listed on each alert."
            : "A new secret is shown once and the receiver must be updated to accept it. Deliveries already queued keep their original key."
        }
        confirmLabel={pending?.kind === "remove" ? (busy?.startsWith("delete:") ? "Removing…" : "Remove destination") : busy?.startsWith("rotate:") ? "Rotating…" : "Rotate secret"}
        busy={Boolean(busy?.startsWith("delete:") || busy?.startsWith("rotate:"))}
        error={pendingError || undefined}
      />
    </PageStack>
  );
}
