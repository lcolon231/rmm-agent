// SPDX-License-Identifier: AGPL-3.0-only

import { ArrowLeft, Clock3, FileClock, ListChecks } from "lucide-react";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";

import { getDashboardSession } from "@/lib/dashboard-session";
import {
  describeThreshold,
  formatCheckInterval,
  formatCheckType,
  formatMonitoringScope,
  formatMonitoringTimestamp,
} from "@/lib/monitoring-core";
import { getMonitoringPolicy } from "@/lib/monitoring";
import { NodelinkApiError } from "@/lib/nodelink-api";

export const dynamic = "force-dynamic";

export default async function MonitoringPolicyPage({
  params,
}: {
  params: Promise<{ policyId: string }>;
}) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");
  const { policyId } = await params;

  let policy;
  try {
    policy = await getMonitoringPolicy(session.sessionToken, policyId);
  } catch (error) {
    if (error instanceof NodelinkApiError && error.status === 404) notFound();
    return (
      <section className="enrollment-empty" role="alert">
        <h1>Monitoring policy is unavailable</h1>
        <p>No check definitions are shown because the policy response could not be verified.</p>
        <Link href="/monitoring">Return to monitoring policies</Link>
      </section>
    );
  }

  return (
    <>
      <header className="enrollment-page-head">
        <div>
          <span>{formatMonitoringScope(policy.scope)} policy Â· revision {policy.current_version}</span>
          <h1>{policy.name}</h1>
          <p>
            {policy.scope_id ? `Target ${policy.scope_id}` : "Applies to every managed endpoint"}.
            This view shows the current check set and every append-only revision.
          </p>
        </div>
        <Link className="enrollment-primary-link" href="/monitoring">
          <ArrowLeft size={16} /> All policies
        </Link>
      </header>

      <div className="monitoring-summary-grid">
        <section>
          <span>Status</span>
          <strong>{policy.enabled ? "Enabled" : "Disabled"}</strong>
        </section>
        <section>
          <span>Current revision</span>
          <strong>v{policy.current_version}</strong>
        </section>
        <section>
          <span>Configured checks</span>
          <strong>{policy.check_count}</strong>
        </section>
        <section>
          <span>Created</span>
          <strong>{formatMonitoringTimestamp(policy.created_at)}</strong>
        </section>
      </div>

      <section className="enrollment-panel">
        <header>
          <div>
            <span>Current configuration</span>
            <h2>{policy.checks.length} check{policy.checks.length === 1 ? "" : "s"}</h2>
            <small>Disabled definitions remove an inherited check with the same key.</small>
          </div>
          <ListChecks aria-hidden="true" size={19} />
        </header>
        {policy.checks.length === 0 ? (
          <div className="enrollment-empty">
            <ListChecks size={24} />
            <h3>This revision has no checks</h3>
            <p>An empty policy contributes no checks to effective-policy resolution.</p>
          </div>
        ) : (
          <div className="monitoring-check-grid">
            {policy.checks.map((check) => (
              <article className={check.enabled ? "" : "disabled"} key={check.key}>
                <header>
                  <div>
                    <code>{check.key}</code>
                    <h3>{formatCheckType(check.type)}</h3>
                  </div>
                  <span>{check.enabled ? "Active" : "Removes inherited key"}</span>
                </header>
                <dl>
                  <div><dt>Schedule</dt><dd>{formatCheckInterval(check.schedule.interval_seconds)}</dd></div>
                  <div><dt>Threshold</dt><dd>{describeThreshold(check.threshold)}</dd></div>
                  <div>
                    <dt>Hysteresis</dt>
                    <dd>{check.hysteresis.raise_samples} raise / {check.hysteresis.clear_samples} clear</dd>
                  </div>
                  <div>
                    <dt>Parameters</dt>
                    <dd>{formatParams(check.params)}</dd>
                  </div>
                </dl>
              </article>
            ))}
          </div>
        )}
      </section>

      <section className="enrollment-panel">
        <header>
          <div>
            <span>Append-only history</span>
            <h2>{policy.revisions.length} revision{policy.revisions.length === 1 ? "" : "s"}</h2>
            <small>Newest first. Historical rows are never edited in place.</small>
          </div>
          <FileClock aria-hidden="true" size={19} />
        </header>
        <div className="monitoring-revisions">
          {policy.revisions.map((revision) => (
            <article key={revision.id}>
              <span className="monitoring-revision-number">v{revision.version}</span>
              <div>
                <strong>{revision.checks.length} check{revision.checks.length === 1 ? "" : "s"}</strong>
                <p>{revision.change_note || "No change note was provided."}</p>
                <small>
                  <Clock3 aria-hidden="true" size={13} /> {formatMonitoringTimestamp(revision.created_at)}
                  {revision.created_by ? ` Â· ${revision.created_by}` : ""}
                </small>
              </div>
            </article>
          ))}
        </div>
      </section>
    </>
  );
}

function formatParams(params: Record<string, unknown>): string {
  const entries = Object.entries(params).sort(([left], [right]) => left.localeCompare(right));
  if (entries.length === 0) return "None";
  return entries.map(([key, value]) => `${key.replaceAll("_", " ")}: ${String(value)}`).join(" Â· ");
}
