// SPDX-License-Identifier: AGPL-3.0-only

"use client";

import {
  ArrowRight,
  Building2,
  CheckCircle2,
  MapPin,
  ShieldCheck,
} from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import {
  validateClientCreateInput,
  validateSiteCreateInput,
  type ClientRecord,
  type SiteRecord,
} from "@/lib/client-site-management-core";
import type { NavigationClient } from "@/lib/client-navigation";

type ClientResponse = { client?: ClientRecord; error?: string };
type SiteResponse = { site?: SiteRecord; error?: string };

export function ClientSiteSetup({
  initialClients,
}: {
  initialClients: NavigationClient[];
}) {
  const [clients, setClients] = useState(initialClients);
  const [selectedClientId, setSelectedClientId] = useState(
    initialClients[0]?.id ?? "",
  );
  const [clientError, setClientError] = useState("");
  const [siteError, setSiteError] = useState("");
  const [clientPending, setClientPending] = useState(false);
  const [sitePending, setSitePending] = useState(false);
  const [createdClient, setCreatedClient] = useState<ClientRecord | null>(null);
  const [createdSite, setCreatedSite] = useState<SiteRecord | null>(null);

  async function createClient(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setClientError("");
    const form = event.currentTarget;
    const input = validateClientCreateInput({
      name: new FormData(form).get("client_name"),
    });
    if (!input) {
      setClientError("Enter a client name between 1 and 200 characters.");
      return;
    }
    setClientPending(true);
    try {
      const response = await fetch("/api/clients", {
        body: JSON.stringify(input),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      const body = await response.json().catch(() => null) as ClientResponse | null;
      if (!response.ok || !body?.client) {
        setClientError(body?.error ?? "The client could not be created.");
        return;
      }
      const client = body.client;
      setClients((current) => [
        ...current,
        { id: client.id, name: client.name, sites: [] },
      ]);
      setCreatedClient(client);
      setSelectedClientId(client.id);
      setCreatedSite(null);
      form.reset();
    } catch {
      setClientError("Client creation is unavailable. Check the management service.");
    } finally {
      setClientPending(false);
    }
  }

  async function createSite(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSiteError("");
    const form = event.currentTarget;
    const input = validateSiteCreateInput({
      client_id: selectedClientId,
      name: new FormData(form).get("site_name"),
    });
    if (!input) {
      setSiteError("Select a client and enter a site name between 1 and 200 characters.");
      return;
    }
    setSitePending(true);
    try {
      const response = await fetch("/api/sites", {
        body: JSON.stringify(input),
        headers: { "Content-Type": "application/json" },
        method: "POST",
      });
      const body = await response.json().catch(() => null) as SiteResponse | null;
      if (!response.ok || !body?.site) {
        setSiteError(body?.error ?? "The site could not be created.");
        return;
      }
      const site = body.site;
      setClients((current) => current.map((client) => (
        client.id === site.client_id
          ? {
              ...client,
              sites: [
                ...client.sites,
                {
                  id: site.id,
                  client_id: site.client_id,
                  name: site.name,
                  endpoint_count: 0,
                },
              ],
            }
          : client
      )));
      setCreatedSite(site);
      form.reset();
    } catch {
      setSiteError("Site creation is unavailable. Check the management service.");
    } finally {
      setSitePending(false);
    }
  }

  return (
    <>
      <section className="setup-boundary-banner">
        <ShieldCheck aria-hidden="true" size={22} />
        <div>
          <strong>First-run provisioning</strong>
          <span>
            Create the customer record first, then a site where enrollment tokens
            and endpoint identities will be assigned. Both actions are authorized
            and recorded in the audit log.
          </span>
        </div>
      </section>

      <div className="client-site-setup-grid">
        <form className="client-site-setup-card" onSubmit={createClient}>
          <header>
            <span className="setup-step">01</span>
            <Building2 aria-hidden="true" size={20} />
            <div>
              <span>Customer boundary</span>
              <h2>Create client</h2>
            </div>
          </header>
          <p>
            A client groups its sites and enrolled endpoints. Names must be unique
            across this NodeLink deployment.
          </p>
          <label htmlFor="setup-client-name">
            Client name
            <input
              autoComplete="organization"
              id="setup-client-name"
              maxLength={200}
              name="client_name"
              placeholder="North Clinic"
              required
            />
          </label>
          {clientError ? (
            <section className="enrollment-form-error" role="alert">
              <strong>Client was not created</strong>
              <span>{clientError}</span>
            </section>
          ) : null}
          {createdClient ? (
            <p className="setup-success" role="status">
              <CheckCircle2 aria-hidden="true" size={15} />
              {createdClient.name} created and selected for the next step.
            </p>
          ) : null}
          <footer>
            <button className="primary" disabled={clientPending} type="submit">
              <Building2 aria-hidden="true" size={16} />
              {clientPending ? "Creating..." : "Create client"}
            </button>
          </footer>
        </form>

        <form className="client-site-setup-card" onSubmit={createSite}>
          <header>
            <span className="setup-step">02</span>
            <MapPin aria-hidden="true" size={20} />
            <div>
              <span>Enrollment destination</span>
              <h2>Create site</h2>
            </div>
          </header>
          <p>
            Site names must be unique within their client. Every enrollment token
            is bound to one site.
          </p>
          <label htmlFor="setup-site-client">
            Client
            <select
              disabled={clients.length === 0}
              id="setup-site-client"
              onChange={(event) => setSelectedClientId(event.target.value)}
              required
              value={selectedClientId}
            >
              {clients.length === 0 ? <option value="">Create a client first</option> : null}
              {clients.map((client) => (
                <option key={client.id} value={client.id}>{client.name}</option>
              ))}
            </select>
          </label>
          <label htmlFor="setup-site-name">
            Site name
            <input
              disabled={clients.length === 0}
              id="setup-site-name"
              maxLength={200}
              name="site_name"
              placeholder="Headquarters"
              required
            />
          </label>
          {siteError ? (
            <section className="enrollment-form-error" role="alert">
              <strong>Site was not created</strong>
              <span>{siteError}</span>
            </section>
          ) : null}
          {createdSite ? (
            <p className="setup-success" role="status">
              <CheckCircle2 aria-hidden="true" size={15} />
              {createdSite.name} is ready for enrollment.
            </p>
          ) : null}
          <footer>
            <button
              className="primary"
              disabled={sitePending || clients.length === 0}
              type="submit"
            >
              <MapPin aria-hidden="true" size={16} />
              {sitePending ? "Creating..." : "Create site"}
            </button>
          </footer>
        </form>
      </div>

      {createdSite ? (
        <section className="setup-next-step">
          <CheckCircle2 aria-hidden="true" size={24} />
          <div>
            <span>Provisioning boundary ready</span>
            <h2>Create the first enrollment token</h2>
            <p>
              Continue with <strong>{createdSite.name}</strong> preselected. The
              plaintext enrollment token will be shown only once.
            </p>
          </div>
          <Link href={`/enrollment/tokens/new?site=${encodeURIComponent(createdSite.id)}`}>
            Create token <ArrowRight aria-hidden="true" size={16} />
          </Link>
        </section>
      ) : null}
    </>
  );
}
