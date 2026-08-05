// SPDX-License-Identifier: AGPL-3.0-only
import { redirect } from "next/navigation";
import { ScriptLibraryView } from "@/components/script-library-view";
import { getDashboardSession } from "@/lib/dashboard-session";
import { listScripts } from "@/lib/script-library";

export default async function ScriptsPage() {
  const session = await getDashboardSession(); if (session.kind !== "authenticated") redirect("/login");
  let scripts = null; let error = "";
  try { scripts = await listScripts(session.sessionToken); } catch { error = "The library response could not be verified. No script records are shown."; }
  return <ScriptLibraryView initialList={scripts} initialError={error} role={session.operator.role} />;
}
