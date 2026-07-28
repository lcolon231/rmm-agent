import Link from "next/link";

export default function AgentNotFound() {
  return <section className="enrollment-empty"><h1>Agent not found</h1><p>The identity may have been removed from this deployment or the link is invalid.</p><Link href="/enrollment/agents">Return to inventory</Link></section>;
}
