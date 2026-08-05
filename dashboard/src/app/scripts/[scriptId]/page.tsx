// SPDX-License-Identifier: AGPL-3.0-only
import { redirect } from "next/navigation";
import { ScriptDetailView } from "@/components/script-detail-view";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getScript, getScriptVersion } from "@/lib/script-library";

export default async function ScriptPage({ params }: { params: Promise<{ scriptId: string }> }) {
  const session = await getDashboardSession(); if (session.kind !== "authenticated") redirect("/login");
  const { scriptId } = await params;
  let script = null;
  let latestContent = "";
  try {
    script = await getScript(session.sessionToken, scriptId);
    const latest = await getScriptVersion(session.sessionToken, scriptId, script.latest_version);
    latestContent = latest.content ?? "";
  } catch {
    script = null;
  }
  if (!script) return <section className="script-unavailable" role="alert"><span>Unavailable</span><h1>Script evidence could not be loaded</h1><p>The record may not exist, or the service response could not be verified. No cached content is shown.</p></section>;
  return <ScriptDetailView initialScript={script} latestContent={latestContent} role={session.operator.role} />;
}
