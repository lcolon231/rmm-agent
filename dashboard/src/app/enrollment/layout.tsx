// SPDX-License-Identifier: AGPL-3.0-only

import { EnrollmentShell } from "@/components/enrollment/enrollment-shell";
import { getDashboardSession } from "@/lib/dashboard-session";
import { redirect } from "next/navigation";

export const dynamic = "force-dynamic";

export default async function EnrollmentLayout({ children }: { children: React.ReactNode }) {
  const session = await getDashboardSession();
  if (session.kind === "anonymous") redirect("/login");
  if (session.kind === "unavailable") {
    return <main className="enrollment-standalone-error"><h1>Enrollment management is unavailable</h1><p>Your session could not be verified. No protected data was loaded.</p></main>;
  }
  return <EnrollmentShell operator={session.operator}>{children}</EnrollmentShell>;
}
