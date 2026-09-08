// SPDX-License-Identifier: AGPL-3.0-only

import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { MfaChallengeForm } from "@/components/mfa-challenge-form";
import { mfaCookieName, type MfaMethod } from "@/lib/mfa-core";
import { getDashboardSession } from "@/lib/dashboard-session";

export const dynamic = "force-dynamic";

type MfaPageProps = {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
};

/**
 * The challenge step of signing in (issue #67).
 *
 * Reaching this page requires the restricted cookie to exist, which only the
 * login route sets and only after a correct password. Without it there is
 * nothing to complete, so the visitor is sent back to sign in rather than shown
 * a form that cannot work.
 */
export default async function MfaChallengePage({ searchParams }: MfaPageProps) {
  const session = await getDashboardSession();
  if (session.kind === "authenticated") {
    redirect("/");
  }

  const store = await cookies();
  if (!store.get(mfaCookieName())?.value) {
    redirect("/login");
  }

  // The available methods are display hints only; the server re-decides them on
  // every request, so a tampered query string can widen nothing.
  const query = await searchParams;
  const raw = Array.isArray(query.methods) ? query.methods[0] : query.methods;
  const hinted = (raw ?? "")
    .split(",")
    .filter((method): method is MfaMethod =>
      method === "webauthn"
      || method === "recovery_code"
      || method === "email_code"
      || method === "enrollment");

  // A page reload loses the hint. Offering every path in that case is safe and
  // kinder than hiding one: the server re-decides on each request and refuses
  // any method the operator is not actually entitled to, so a widened hint
  // grants nothing. The email option is deliberately included here -- an
  // operator who has only that factor would otherwise be stranded by a reload
  // on a page offering them a key they do not have.
  const methods: MfaMethod[] = hinted.length > 0
    ? hinted
    : ["webauthn", "recovery_code", "email_code"];

  const enroll = (Array.isArray(query.enroll) ? query.enroll[0] : query.enroll) === "1"
    || hinted.includes("enrollment");

  return <MfaChallengeForm enrollmentRequired={enroll} methods={methods} />;
}
