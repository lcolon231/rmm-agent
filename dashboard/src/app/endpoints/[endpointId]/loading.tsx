// SPDX-License-Identifier: AGPL-3.0-only

export default function EndpointLoading() {
  return (
    <main className="endpoint-detail-page" aria-busy="true" aria-label="Loading endpoint details">
      <div className="detail-loading-bar" />
      <div className="detail-workspace detail-loading">
        <div className="loading-block short" />
        <div className="loading-block identity" />
        <div className="loading-grid">{Array.from({ length: 4 }, (_, index) => <div className="loading-block" key={index} />)}</div>
        <div className="loading-block chart" />
      </div>
    </main>
  );
}
