# NodeLink dashboard

The NodeLink dashboard is a Next.js technician interface. This first foundation
provides a responsive, accessible operations overview with fixture data, a
server-mediated operator sign-in boundary, and live client/site navigation.

It is not yet a live endpoint console and must not be used to manage production
or regulated endpoints.

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

## Foundation boundary

- No dashboard mutation, browser token, or persisted dashboard state exists
  yet. The signed-in overview remains fixture-backed, except for read-only
  client/site navigation. No schema migration is required for that API.
- The API client makes no automatic retry. Later mutation workflows must define
  explicit idempotency and retry behavior before they use it.
- Rollback is deployment-level: remove or disable the dashboard service without
  changing the agent, FastAPI server, or database schema.
- The dashboard requires Node.js 24 and a compatible NodeLink API origin; it
  does not change existing agent or server protocol compatibility.

See `../docs/DASHBOARD-DESIGN.md` for the product and interaction design.
