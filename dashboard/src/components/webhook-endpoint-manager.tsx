// SPDX-License-Identifier: AGPL-3.0-only
"use client";

import {
  Check,
  Clipboard,
  KeyRound,
  Link2,
  LoaderCircle,
  Pencil,
  Plus,
  RefreshCw,
  ShieldCheck,
  Trash2,
  Webhook,
  X,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import {
  formatMonitoringTimestamp,
  type WebhookDestinationValidation,
  type WebhookEndpoint,
  type WebhookEndpointSecret,
  type WebhookEventType,
  type WebhookStatus,
} from "@/lib/monitoring-core";

const eventOptions: Array<{ value: WebhookEventType; label: string }> = [
  { value: "opened", label: "Opened" },
  { value: "reopened", label: "Reopened" },
  { value: "acknowledged", label: "Acknowledged" },
  { value: "manual_resolution", label: "Manual resolution" },
  { value: "automatic_recovery", label: "Automatic recovery" },
  { value: "policy_revised", label: "Policy revised" },
  { value: "policy_deleted", label: "Policy deleted" },
  { value: "policy_superseded", label: "Policy superseded" },
];

const defaultEvents: WebhookEventType[] = [
  "opened", "reopened", "acknowledged", "manual_resolution", "automatic_recovery",
];

function requestId() {
  return crypto.randomUUID().replaceAll("-", "");
}

function eventLabel(value: WebhookEventType) {
  return eventOptions.find((item) => item.value === value)?.label ?? value;
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
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [events, setEvents] = useState<WebhookEventType[]>(defaultEvents);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [secretReveal, setSecretReveal] = useState<WebhookEndpointSecret | null>(null);
  const [copied, setCopied] = useState(false);
  const [validations, setValidations] = useState<Record<string, WebhookDestinationValidation>>({});
  const [editing, setEditing] = useState<string | null>(null);
  const [editName, setEditName] = useState("");
  const [editUrl, setEditUrl] = useState("");
  const [editEvents, setEditEvents] = useState<WebhookEventType[]>([]);

  function toggleEvent(
    value: WebhookEventType,
    selected: WebhookEventType[],
    update: (next: WebhookEventType[]) => void,
  ) {
    update(selected.includes(value)
      ? selected.filter((item) => item !== value)
      : [...selected, value]);
  }

  async function responseBody<T>(response: Response): Promise<T> {
    const body = await response.json().catch(() => null) as (T & { error?: string }) | null;
    if (!response.ok || !body) throw new Error(body?.error ?? "The change could not be confirmed.");
    return body;
  }

  async function create(event: React.FormEvent<HTMLFormElement>) {
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
      const response = await fetch(
        `/api/webhook-endpoints/${encodeURIComponent(endpoint.id)}/validate`,
        { method: "POST" },
      );
      const body = await responseBody<{ validation: WebhookDestinationValidation }>(response);
      setValidations((current) => ({ ...current, [endpoint.id]: body.validation }));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Validation could not be completed.");
    } finally {
      setBusy(null);
    }
  }

  async function update(
    endpoint: WebhookEndpoint,
    change: Partial<Pick<WebhookEndpoint, "name" | "enabled" | "event_types">> & { url?: string },
  ) {
    setBusy(`update:${endpoint.id}`);
    setError("");
    try {
      const response = await fetch(`/api/webhook-endpoints/${encodeURIComponent(endpoint.id)}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          request_id: requestId(), expected_version: endpoint.version, ...change,
        }),
      });
      const body = await responseBody<{ endpoint: WebhookEndpoint }>(response);
      setEndpoints((current) => current.map((item) => (
        item.id === endpoint.id ? body.endpoint : item
      )));
      setEditing(null);
      router.refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The endpoint could not be updated.");
    } finally {
      setBusy(null);
    }
  }

  async function rotate(endpoint: WebhookEndpoint) {
    if (!window.confirm(`Rotate the signing secret for ${endpoint.name}? Existing queued deliveries keep their original key.`)) return;
    setBusy(`rotate:${endpoint.id}`);
    setError("");
    try {
      const response = await fetch(
        `/api/webhook-endpoints/${encodeURIComponent(endpoint.id)}/rotate`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ request_id: requestId(), expected_version: endpoint.version }),
        },
      );
      const body = await responseBody<{ endpoint: WebhookEndpointSecret }>(response);
      const rotatedEndpoint = publicEndpoint(body.endpoint);
      setEndpoints((current) => current.map((item) => (
        item.id === endpoint.id ? rotatedEndpoint : item
      )));
      setSecretReveal(body.endpoint);
      setCopied(false);
      router.refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The secret could not be rotated.");
    } finally {
      setBusy(null);
    }
  }

  async function remove(endpoint: WebhookEndpoint) {
    if (!window.confirm(`Remove ${endpoint.name}? Its historical delivery ledger remains available.`)) return;
    setBusy(`delete:${endpoint.id}`);
    setError("");
    try {
      const response = await fetch(`/api/webhook-endpoints/${encodeURIComponent(endpoint.id)}`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ request_id: requestId(), expected_version: endpoint.version }),
      });
      await responseBody<{ deleted: true }>(response);
      setEndpoints((current) => current.filter((item) => item.id !== endpoint.id));
      router.refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The endpoint could not be removed.");
    } finally {
      setBusy(null);
    }
  }

  function beginEdit(endpoint: WebhookEndpoint) {
    setEditing(endpoint.id);
    setEditName(endpoint.name);
    setEditUrl("");
    setEditEvents(endpoint.event_types);
  }

  async function copySecret() {
    if (!secretReveal) return;
    await navigator.clipboard.writeText(secretReveal.secret);
    setCopied(true);
  }

  return (
    <>
      <section className="webhook-signal-path" aria-label="Webhook delivery contract">
        <span><Link2 size={16} /> Public HTTPS destination</span>
        <i aria-hidden="true" />
        <span><KeyRound size={16} /> HMAC-SHA256 · v1</span>
        <i aria-hidden="true" />
        <span><ShieldCheck size={16} /> Pinned address + TLS name</span>
      </section>

      <section className="monitoring-summary-grid webhook-summary-grid">
        <section><span>Destinations</span><strong>{endpoints.length} / {status.endpoint_limit}</strong></section>
        <section><span>Enabled</span><strong>{endpoints.filter((item) => item.enabled).length}</strong></section>
        <section><span>Delivered</span><strong>{status.counts.delivered ?? 0}</strong></section>
        <section><span>Failed</span><strong>{status.counts.failed ?? 0}</strong></section>
      </section>

      {!status.encryption_key_configured ? (
        <section className="webhook-config-warning" role="alert">
          <KeyRound size={19} />
          <div><strong>Secret encryption is unavailable</strong><span>Set WEBHOOK_SECRET_ENCRYPTION_KEY before creating or rotating destinations.</span></div>
        </section>
      ) : null}

      {secretReveal ? (
        <section className="webhook-secret-reveal" role="status">
          <div><span>Copy now · shown once</span><h2>{secretReveal.name} signing secret</h2><p>Store this in the receiving service. NodeLink keeps only an encrypted copy and will not show it again.</p></div>
          <code>{secretReveal.secret}</code>
          <div className="webhook-secret-actions">
            <button type="button" onClick={copySecret}>{copied ? <Check size={14} /> : <Clipboard size={14} />}{copied ? "Copied" : "Copy secret"}</button>
            <button type="button" onClick={() => setSecretReveal(null)}><X size={14} /> Dismiss</button>
          </div>
        </section>
      ) : null}

      {canAdmin ? (
        <section className="enrollment-panel webhook-create-panel">
          <header><div><span>New destination</span><h2>Connect an alert receiver</h2><small>The URL is resolved and checked before any secret is created.</small></div><Plus size={19} /></header>
          <form onSubmit={create}>
            <label><span>Name</span><input value={name} onChange={(event) => setName(event.target.value)} maxLength={200} placeholder="Primary incident relay" required /></label>
            <label><span>Public HTTPS URL</span><input value={url} onChange={(event) => setUrl(event.target.value)} maxLength={2048} placeholder="https://hooks.example.com/nodelink" inputMode="url" required /></label>
            <fieldset>
              <legend>Alert transitions</legend>
              {eventOptions.map((item) => <label key={item.value}><input type="checkbox" checked={events.includes(item.value)} onChange={() => toggleEvent(item.value, events, setEvents)} /><span>{item.label}</span></label>)}
            </fieldset>
            <button type="submit" disabled={busy === "create" || events.length === 0 || !status.encryption_key_configured}>{busy === "create" ? <LoaderCircle className="spin" size={15} /> : <Webhook size={15} />} Create destination</button>
          </form>
        </section>
      ) : null}

      <section className="enrollment-panel webhook-endpoint-panel">
        <header><div><span>Destination register</span><h2>{endpoints.length} signed webhook destinations</h2><small>URLs are masked after save. Paths, query values, and secrets never return to the dashboard.</small></div><Webhook size={19} /></header>
        {endpoints.length ? <div className="webhook-endpoint-list">
          {endpoints.map((endpoint) => {
            const validation = validations[endpoint.id];
            const isEditing = editing === endpoint.id;
            return <article key={endpoint.id} className={endpoint.enabled ? "enabled" : "disabled"}>
              <span className="webhook-endpoint-rail" aria-hidden="true" />
              <div className="webhook-endpoint-main">
                <div className="webhook-endpoint-title"><div><strong>{endpoint.name}</strong><code>{endpoint.url}</code></div><span className={`monitoring-status ${endpoint.enabled ? "enabled" : "disabled"}`}>{endpoint.enabled ? "Enabled" : "Disabled"}</span></div>
                <div className="webhook-event-tags">{endpoint.event_types.map((item) => <span key={item}>{eventLabel(item)}</span>)}</div>
                <dl><div><dt>Signing key</dt><dd>v{endpoint.current_secret_version} · <code>{endpoint.current_secret_key_id.slice(0, 8)}…</code></dd></div><div><dt>Updated</dt><dd>{formatMonitoringTimestamp(endpoint.updated_at)}</dd></div>{validation ? <div><dt>Validation</dt><dd className={`webhook-validation ${validation.state}`}>{validation.state}{validation.code ? ` · ${validation.code.replaceAll("_", " ")}` : ` · ${validation.resolved_address_count} public address${validation.resolved_address_count === 1 ? "" : "es"}`}</dd></div> : null}</dl>
                {isEditing ? <form className="webhook-edit-form" onSubmit={(event) => { event.preventDefault(); void update(endpoint, { name: editName, event_types: editEvents, ...(editUrl.trim() ? { url: editUrl.trim() } : {}) }); }}>
                  <label><span>Name</span><input value={editName} onChange={(event) => setEditName(event.target.value)} required /></label>
                  <label><span>Replace URL <small>(leave blank to keep it)</small></span><input value={editUrl} onChange={(event) => setEditUrl(event.target.value)} placeholder="https://new.example.com/nodelink" /></label>
                  <fieldset><legend>Transitions</legend>{eventOptions.map((item) => <label key={item.value}><input type="checkbox" checked={editEvents.includes(item.value)} onChange={() => toggleEvent(item.value, editEvents, setEditEvents)} /><span>{item.label}</span></label>)}</fieldset>
                  <div><button type="submit" disabled={editEvents.length === 0 || busy === `update:${endpoint.id}`}>Save changes</button><button type="button" onClick={() => setEditing(null)}>Cancel</button></div>
                </form> : null}
              </div>
              <div className="webhook-endpoint-actions">
                {canOperate ? <button type="button" onClick={() => validate(endpoint)} disabled={Boolean(busy)}><RefreshCw size={13} /> {busy === `validate:${endpoint.id}` ? "Checking…" : "Validate"}</button> : null}
                {canAdmin ? <>
                  <button type="button" onClick={() => beginEdit(endpoint)} disabled={Boolean(busy)}><Pencil size={13} /> Edit</button>
                  <button type="button" onClick={() => update(endpoint, { enabled: !endpoint.enabled })} disabled={Boolean(busy)}>{endpoint.enabled ? "Disable" : "Enable"}</button>
                  <button type="button" onClick={() => rotate(endpoint)} disabled={Boolean(busy)}><KeyRound size={13} /> Rotate secret</button>
                  <button className="danger" type="button" onClick={() => remove(endpoint)} disabled={Boolean(busy)}><Trash2 size={13} /> Remove</button>
                </> : null}
              </div>
            </article>;
          })}
        </div> : <div className="enrollment-empty"><Webhook size={25} /><h3>No webhook destinations</h3><p>{canAdmin ? "Create the first destination to send signed alert transitions." : "An administrator has not configured a destination yet."}</p></div>}
      </section>
      {error ? <p className="alert-action-error" role="alert">{error}</p> : null}
    </>
  );
}
