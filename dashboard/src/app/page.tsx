// SPDX-License-Identifier: AGPL-3.0-only

import { DashboardShell } from "@/components/dashboard-shell";
import { getDashboardSession } from "@/lib/dashboard-session";
import Link from "next/link";
import { redirect } from "next/navigation";

export const dynamic = "force-dynamic";

export default async function Home() {
  const session = await getDashboardSession();
  if (session.kind === "anonymous") {
    redirect("/login");
  }

  if (session.kind === "unavailable") {
    return (
      <main className="login-page">
        <section className="login-panel login-status" aria-labelledby="session-status-title">
          <span className="login-eyebrow">Session verification</span>
          <h1 id="session-status-title">Operations is temporarily unavailable</h1>
          <p>NodeLink could not verify your operator session. Your dashboard data remains protected. Try again shortly.</p>
          <Link className="login-link" href="/">Try again</Link>
        </section>
      </main>
    );
  }

  return <DashboardShell operator={session.operator} />;
}
