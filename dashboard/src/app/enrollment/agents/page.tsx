// SPDX-License-Identifier: AGPL-3.0-only

import { Monitor } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";

import { RevokeAction } from "@/components/enrollment/revoke-action";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getEnrollmentAgents } from "@/lib/enrollment";
import { formatEnrollmentDateTime } from "@/lib/enrollment-core";

export default async function EnrollmentAgentsPage() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");
  const agents = await getEnrollmentAgents(session.sessionToken);
  return (
    <>
      <header className="enrollment-page-head"><div><span>Registered identities</span><h1>Agent inventory</h1><p>Enrollment assignment, runtime status, credential state, and endpoint identity.</p></div></header>
      <section className="enrollment-panel">
        <header><div><span>Managed endpoints</span><h2>{agents.length} agent{agents.length === 1 ? "" : "s"}</h2></div></header>
        {agents.length === 0 ? <div className="enrollment-empty"><Monitor size={25} /><h3>No enrolled agents</h3><p>Agents appear here immediately after a successful token redemption.</p></div> : (
          <div className="enrollment-table-wrap"><table><thead><tr><th>Agent</th><th>Hostname</th><th>Environment</th><th>Platform</th><th>Status</th><th>Enrolled</th><th>Last seen</th><th>Credential</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>
            {agents.map((agent) => <tr key={agent.id}>
              <td><Link href={`/enrollment/agents/${agent.id}`}>{agent.name || agent.hostname}</Link><code>{agent.id}</code></td>
              <td>{agent.hostname}</td><td>{agent.environment ?? "Unassigned"}</td>
              <td>{agent.os || "Unknown"}<small>{agent.architecture || agent.os_version || "No architecture"}</small></td>
              <td><span className={`enrollment-badge ${agent.trust_state === "revoked" ? "revoked" : agent.status}`}>{agent.trust_state === "revoked" ? "Revoked" : agent.status}</span></td>
              <td>{formatEnrollmentDateTime(agent.enrolled_at)}</td><td>{formatEnrollmentDateTime(agent.last_seen_at)}</td>
              <td>{agent.credential_fingerprint ? <code>{agent.credential_fingerprint.slice(0, 12)}…</code> : "Legacy"}<small>{agent.credential_expires_at ? `Expires ${formatEnrollmentDateTime(agent.credential_expires_at)}` : "No configured expiry"}</small></td>
              <td>{session.operator.role === "admin" && agent.trust_state !== "revoked" ? <RevokeAction endpoint={`/api/enrollment-agents/${agent.id}/revoke`} label="Revoke agent" subject={agent.name || agent.hostname} /> : null}</td>
            </tr>)}
          </tbody></table></div>
        )}
      </section>
    </>
  );
}
