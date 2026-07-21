// SPDX-License-Identifier: AGPL-3.0-only

export default function Loading() {
  return (
    <main className="dashboard-loading" aria-busy="true" aria-label="Loading dashboard">
      <div className="dashboard-loading-mark" />
      <p>Loading operations…</p>
    </main>
  );
}
