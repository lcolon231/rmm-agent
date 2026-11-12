// SPDX-License-Identifier: AGPL-3.0-only
import Link from "next/link";
import { redirect } from "next/navigation";
import { ScriptDetailView, type ScriptDetailTab } from "@/components/script-detail-view";
import { getDashboardSession } from "@/lib/dashboard-session";
import { getScript, getScriptVersion } from "@/lib/script-library";

const TABS: ScriptDetailTab[] = ["source", "parameters", "versions"];

export default async function ScriptPage({ params, searchParams }: { params: Promise<{ scriptId: string }>; searchParams?: Promise<{ tab?: string | string[] }> }) {
  const session = await getDashboardSession(); if (session.kind !== "authenticated") redirect("/login");
  const { scriptId } = await params;
  const query = (await searchParams) ?? {};
  const tab = TABS.find((item) => item === query.tab) ?? "source";
  let script = null;
  let latestContent = "";
  try {
    script = await getScript(session.sessionToken, scriptId);
    const latest = await getScriptVersion(session.sessionToken, scriptId, script.latest_version);
    latestContent = latest.content ?? "";
  } catch {
    script = null;
  }
  if (!script) {
    // Inside the app shell: a section, not a second <main>.
    return (
      <section role="alert" className="grid max-w-[640px] gap-2 rounded-[10px] border border-(--line) bg-(--paper) p-6">
        <span className="text-xs text-(--muted)">Script library</span>
        <h1 className="m-0 text-2xl font-semibold text-(--ink)">This script could not be loaded</h1>
        <p className="m-0 text-sm text-(--slate)">The record may not exist, or the server response could not be verified. No saved copy is shown. Nothing was changed.</p>
        <p className="m-0 mt-2 text-sm font-semibold"><Link href="/scripts">Back to Script library</Link></p>
      </section>
    );
  }
  return <ScriptDetailView initialScript={script} latestContent={latestContent} role={session.operator.role} tab={tab} />;
}
