// SPDX-License-Identifier: AGPL-3.0-only

import { Plus } from "lucide-react";
import { redirect } from "next/navigation";

import { EnrollmentHeader } from "@/components/enrollment/enrollment-header";
import { EnrollmentTokensView } from "@/components/enrollment/tokens-view";
import { PageStack } from "@/components/shell/page-header";
import { ButtonLink } from "@/components/ui/button";
import { getDashboardSession } from "@/lib/dashboard-session";
import { canManageEnrollment, type EnrollmentTokenStatus } from "@/lib/enrollment-core";
import { getEnrollmentTokens } from "@/lib/enrollment";

export default async function EnrollmentTokensPage({ searchParams }: { searchParams: Promise<{ page?: string; search?: string; status?: string }> }) {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated") redirect("/login");
  const query = await searchParams;
  const status = ["active", "used", "expired", "revoked"].includes(query.status ?? "") ? query.status as EnrollmentTokenStatus : undefined;
  const page = /^\d+$/.test(query.page ?? "") ? Math.max(1, Number(query.page)) : 1;
  const search = query.search?.slice(0, 100);
  const data = await getEnrollmentTokens(session.sessionToken, { page, search, status });
  const canManage = canManageEnrollment(session.operator.role);
  return (
    <PageStack>
      <EnrollmentHeader
        tab="tokens"
        role={session.operator.role}
        trail={[{ label: "Tokens" }]}
        title="Enrollment tokens"
        description="One-time codes that let a new device join a site. Keep them short-lived; a token is shown only once."
        actions={
          canManage ? (
            <ButtonLink href="/enrollment/tokens/new" variant="primary" icon={Plus}>
              New token
            </ButtonLink>
          ) : null
        }
      />
      <EnrollmentTokensView
        tokens={data.items}
        total={data.total}
        pageSize={data.page_size}
        query={{ page, search: search || undefined, status }}
        canManage={canManage}
      />
    </PageStack>
  );
}
