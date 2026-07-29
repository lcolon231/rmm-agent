// SPDX-License-Identifier: AGPL-3.0-only

import { OperatorManagementView } from "@/components/operator-management-view";
import { getDashboardSession } from "@/lib/dashboard-session";

export default async function OperatorsPage() {
  const session = await getDashboardSession();
  if (session.kind !== "authenticated" || session.operator.role !== "admin") {
    return null;
  }
  return <OperatorManagementView currentOperatorId={session.operator.id} />;
}
