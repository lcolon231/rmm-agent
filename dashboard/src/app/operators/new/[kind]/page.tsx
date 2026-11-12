// SPDX-License-Identifier: AGPL-3.0-only

import { ManagedSurface } from "@/components/admin/managed-surface";
import { PageHeader } from "@/components/shell/page-header";
import { notFound } from "next/navigation";

import { CreateOperatorForm } from "@/components/create-operator-form";
import {
  operatorKindLabel,
  type OperatorKind,
} from "@/lib/operator-management-core";

export default async function CreateOperatorPage({
  params,
}: {
  params: Promise<{ kind: string }>;
}) {
  const { kind: rawKind } = await params;
  if (rawKind !== "administrator" && rawKind !== "technician") notFound();
  const kind = rawKind as OperatorKind;
  const label = operatorKindLabel(kind);

  return (
    <ManagedSurface>
<PageHeader breadcrumb={[{ label: "Administration" }, { label: "Create operator" }]} title={`Create ${label.toLowerCase()}`} description="Create a sign-in identity. Script permissions are granted separately." />
      <CreateOperatorForm kind={kind} />
    </ManagedSurface>
  );
}
