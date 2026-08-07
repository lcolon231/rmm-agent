// SPDX-License-Identifier: AGPL-3.0-only
import Link from "next/link";
export default function AlertNotFound() {
  return <div className="enrollment-empty"><h1>Alert not found</h1><p>It may have been removed with its endpoint.</p><Link href="/monitoring">Return to monitoring</Link></div>;
}
