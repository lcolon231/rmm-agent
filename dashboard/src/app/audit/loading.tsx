// SPDX-License-Identifier: AGPL-3.0-only
import { Skeleton } from "@/components/ui/states";
export default function LoadingAudit() { return <div role="status" className="grid gap-6"><p>Loading audit evidence…</p><Skeleton rows={6} /></div>; }

