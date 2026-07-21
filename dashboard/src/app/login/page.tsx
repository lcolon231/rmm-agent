// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";

import { LoginForm } from "@/components/login-form";
import { getDashboardSession } from "@/lib/dashboard-session";

export const dynamic = "force-dynamic";

export default async function LoginPage() {
  const session = await getDashboardSession();
  if (session.kind === "authenticated") {
    redirect("/");
  }

  return <LoginForm initialError={session.kind === "unavailable" ? "NodeLink is unavailable. Sign-in may not succeed until it recovers." : undefined} />;
}
