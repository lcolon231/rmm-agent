// SPDX-License-Identifier: AGPL-3.0-only

import { redirect } from "next/navigation";

import { LoginForm } from "@/components/login-form";
import { loginErrorMessage } from "@/lib/dashboard-auth-core";
import { getDashboardSession } from "@/lib/dashboard-session";

export const dynamic = "force-dynamic";

type LoginPageProps = {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
};

export default async function LoginPage({ searchParams }: LoginPageProps) {
  const session = await getDashboardSession();
  if (session.kind === "authenticated") {
    redirect("/");
  }

  const query = await searchParams;
  if ("email" in query || "password" in query) {
    redirect("/login");
  }

  const errorCode = Array.isArray(query.error) ? query.error[0] : query.error;
  const initialError = session.kind === "unavailable"
    ? "NodeLink is unavailable. Sign-in may not succeed until it recovers."
    : loginErrorMessage(errorCode);

  return <LoginForm initialError={initialError} />;
}
