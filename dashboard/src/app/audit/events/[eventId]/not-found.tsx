// SPDX-License-Identifier: AGPL-3.0-only
import { PageHeader, PageStack } from "@/components/shell/page-header";
import { ButtonLink } from "@/components/ui/button";
export default function AuditEventNotFound() { return <PageStack><PageHeader breadcrumb={[{ label: "Compliance" }, { label: "Audit", href: "/audit" }]} title="Audit event not found" description="No event was found for this identifier. The link may be stale or refer to another deployment." /><ButtonLink href="/audit" variant="secondary">Back to the timeline</ButtonLink></PageStack>; }
