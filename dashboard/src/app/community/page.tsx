// SPDX-License-Identifier: AGPL-3.0-only
import { redirect } from "next/navigation";
import { CommunityRepositoryView } from "@/components/community-repository-view";
import { listCommunityInstalls, listCommunityPackages, listCommunityPublishers } from "@/lib/community-packages";
import type { CommunityInstall, CommunityPackage, CommunityPublisher } from "@/lib/community-packages-core";
import { getDashboardSession } from "@/lib/dashboard-session";

export default async function CommunityPage() {
  const session = await getDashboardSession(); if (session.kind !== "authenticated") redirect("/login");
  let publishers: CommunityPublisher[] | null = null; let packages: CommunityPackage[] | null = null;
  let installs: CommunityInstall[] | null = null; let error = "";
  try {
    const [publisherList, packageList, installList] = await Promise.all([
      listCommunityPublishers(session.sessionToken),
      listCommunityPackages(session.sessionToken),
      listCommunityInstalls(session.sessionToken),
    ]);
    publishers = publisherList; packages = packageList.items; installs = installList;
  } catch {
    error = "The repository response could not be verified. No package records are shown.";
  }
  return <CommunityRepositoryView publishers={error ? null : publishers} packages={error ? null : packages}
    installs={error ? null : installs} initialError={error} role={session.operator.role} />;
}
