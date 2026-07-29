// SPDX-License-Identifier: AGPL-3.0-only

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
    <>
      <header className="operator-page-head compact">
        <div>
          <span>New operator identity</span>
          <h1>Create {label.toLowerCase()}</h1>
          <p>
            Create the sign-in identity now. Script execution remains a separate, default-deny permission.
          </p>
        </div>
      </header>
      <CreateOperatorForm kind={kind} />
    </>
  );
}
