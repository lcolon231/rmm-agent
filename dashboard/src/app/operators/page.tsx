// SPDX-License-Identifier: AGPL-3.0-only

import { OperatorManagementView } from "@/components/operator-management-view";
import { getDashboardSession } from "@/lib/dashboard-session";
import { listOperators } from "@/lib/operator-management";
import { handleListOperators } from "@/lib/operator-management-route-core";
import type { OperatorRecord } from "@/lib/operator-management-core";

type InitialOperatorList = {
  error?: string;
  operators?: OperatorRecord[];
};

export default async function OperatorsPage() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated" || session.operator.role !== "admin") {
    return null;
  }

  const response = await handleListOperators(
    new Request("http://nodelink.local/api/operators"),
    {
      getSession: async () => session,
      listOperators,
    },
  );
  const body = await response.json().catch(() => null) as InitialOperatorList | null;

  return (
    <OperatorManagementView
      currentOperatorId={session.operator.id}
      initialError={body?.error ?? (body?.operators ? "" : "Operator records are unavailable. Try again.")}
      initialOperators={body?.operators ?? null}
    />
  );
}
