# NodeLink dashboard

The NodeLink dashboard is a Next.js technician interface. This foundation
provides a responsive, accessible operations overview, a server-mediated
operator sign-in boundary, and live read-only client/site navigation, endpoint
inventory, and endpoint telemetry detail.

Aggregate overview and audit panels remain fixture-backed, and the interface
does not dispatch commands or mutate endpoints. It must not be used to manage
production or regulated endpoints.

## Local development

1. Use Node.js `24.15.0` (see `.nvmrc`).
2. Copy `.env.example` to `.env.local` and adjust the local API URL if needed.
3. Install dependencies and start the development server:

   ```bash
   npm ci
   npm run dev
   ```

4. Open `http://localhost:3000`.

The dashboard health route is available at `/api/health`. It returns `degraded`
when the configured NodeLink API is unavailable without exposing the configured
URL or credentials.

## Configuration

`NODELINK_API_BASE_URL` is read only by server-side code. Do not create a
`NEXT_PUBLIC_` version of this variable, and never put an operator bearer token
in browser storage or a public environment variable.

- Development defaults to `http://127.0.0.1:8000`.
- Production requires an explicit origin URL with no path, query, or fragment.
- HTTP is accepted only for loopback API URLs; remote API URLs must use HTTPS.
- `NODELINK_API_TIMEOUT_MS` is optional and must be between 1000 and 60000.

## Checks

```bash
npm run validate:env
npm run lint
npm run typecheck
npm test
npm run build
```

The API-client boundary lives in `src/lib/nodelink-api.ts`. Browser code never
receives an API bearer token: the login route stores the JWT in an HTTP-only,
same-site cookie and server code forwards it only after revalidating the
operator through `/api/v1/auth/me`. Sign out clears the local cookie and asks
the API to revoke the current token generation.

Client navigation uses `GET /api/v1/clients/navigation`; it returns at most 200
clients with their sites and endpoint counts. The server validates a signed-in
operator, records a redacted audit event for each successful list or detail
view, and returns `401`, `404`, or `503` without exposing credentials. The
dashboard renders loading, empty, unavailable, and invalid-deep-link states;
it does not retry automatically. URL state is `?client=<id>&site=<id>`.

Endpoint inventory uses `GET /api/v1/endpoints` with a maximum page size of
100 (the dashboard uses 25). It supports client/site scope, status, hostname
search, `hostname`/`status`/`last_seen` sorting, and `page` URL state. Only the
latest heartbeat telemetry is shown; raw inventory and agent credentials are
never returned. The endpoint API is readonly, audited, and needs no migration;
remove the dashboard deployment to roll it back without changing agents.

Endpoint detail uses `GET /api/v1/endpoints/{endpoint_id}`. The dashboard asks
for a selectable 6-hour, 24-hour, 3-day, or 7-day window and the API enforces a
1-to-168-hour window plus a 10-to-500 sample limit. It returns endpoint identity,
current state, the latest heartbeat, and a chronological bounded history from
the existing heartbeat table. The latest sample is evaluated independently of
the selected history window so the interface can distinguish current, stale,
and unavailable telemetry. Telemetry is stale after three configured heartbeat
intervals with a five-minute minimum. Missing or unsupported metrics remain
nullable and render as unavailable rather than as zero. Timestamps are displayed
explicitly in UTC, and every chart has a text alternative plus an exact-values
table. Successful reads create a redacted `endpoint_detail.viewed` audit event.

## Foundation boundary

- No dashboard mutation, browser token, or persisted dashboard state exists.
  Aggregate overview and audit panels remain fixture-backed; client/site
  navigation, endpoint inventory, and endpoint telemetry detail are live and
  read-only. No schema migration is required for these APIs.
- The API client makes no automatic retry. Later mutation workflows must define
  explicit idempotency and retry behavior before they use it.
- Rollback is deployment-level: remove or disable the dashboard service without
  changing the agent, FastAPI server, or database schema.
- The dashboard requires Node.js 24 and a compatible NodeLink API origin; it
  does not change existing agent or server protocol compatibility.

See `../docs/DASHBOARD-DESIGN.md` for the product and interaction design.
