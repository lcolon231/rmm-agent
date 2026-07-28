// SPDX-License-Identifier: AGPL-3.0-only

import { Activity, ArrowLeft, KeyRound, ListChecks, Monitor, ShieldCheck } from "lucide-react";
import Link from "next/link";

import type { DashboardOperator } from "@/lib/dashboard-auth-core";

export function EnrollmentShell({
  children,
  operator,
}: {
  children: React.ReactNode;
  operator: DashboardOperator;
}) {
  return (
    <div className="enrollment-app">
      <aside className="enrollment-nav">
        <Link className="enrollment-brand" href="/">
          <span className="brand-mark" aria-hidden="true"><span /><span /><span /></span>
          <span><strong>NodeLink</strong><small>Enrollment control</small></span>
        </Link>
        <nav aria-label="Enrollment management">
          <Link href="/enrollment"><Activity size={18} /> Dashboard</Link>
          <Link href="/enrollment/tokens"><KeyRound size={18} /> Enrollment tokens</Link>
          <Link href="/enrollment/agents"><Monitor size={18} /> Agent inventory</Link>
          <Link href="/enrollment/audit"><ListChecks size={18} /> Audit log</Link>
        </nav>
        <div className="enrollment-nav-trust">
          <ShieldCheck size={18} />
          <span><strong>Server enforced</strong><small>Role and token policy</small></span>
        </div>
        <Link className="enrollment-back" href="/"><ArrowLeft size={16} /> Operations overview</Link>
      </aside>
      <div className="enrollment-workspace">
        <header className="enrollment-topbar">
          <div><span>Secure provisioning</span><strong>Agent enrollment</strong></div>
          <div className="enrollment-operator">
            <span>{operator.role === "admin" ? "Super Administrator" : operator.role === "operator" ? "Administrator" : "Viewer"}</span>
            <strong>{operator.email}</strong>
          </div>
        </header>
        <main className="enrollment-main">{children}</main>
      </div>
    </div>
  );
}
