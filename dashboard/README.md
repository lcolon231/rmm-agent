# NodeLink dashboard

The NodeLink dashboard is a Next.js technician interface. This foundation
provides a responsive, accessible operations overview, a server-mediated
operator sign-in boundary, live client/site navigation, endpoint inventory,
endpoint telemetry detail, and a per-endpoint command console with role-gated
compose-and-confirm dispatch, paginated command history, and per-command
records (envelope evidence, exit code, bounded stdout/stderr with truncation
totals), and administrator-only operator identity management.

Aggregate overview and audit panels remain fixture-backed. It must not be used
to manage production or regulated endpoints.

The `/enrollment` control surface is live: authorized operators can create,
list, filter, and revoke temporary enrollment tokens, view/revoke agent
identities, and review enrollment audit events. Plaintext token values appear
only in the in-memory creation view and are never stored in browser storage or
placed in URLs. Browser mutations use same-origin Route Handlers; FastAPI
independently enforces every role.

`/enrollment/setup` provides the first-run client/site workflow for Technician
and Administrator roles. It creates the customer boundary first, then a site,
and carries the new non-secret site ID into the token form as a preselection.
Client and site names receive distinct duplicate/not-found/authorization
messages; empty enrollment states link to setup instead of presenting an
unusable token form.

The live `/operators` surface is restricted to the API `admin` role. It lists
the complete operator register, creates product-role Administrators (`admin`)
and Technicians (`operator`) through one shared form, presents explicit
default-deny script permission for every role, and provides audited
compose-then-confirm global/site/agent grant and revoke controls plus confirmed
sign-out-everywhere, global-role changes, and disable/re-enable controls. The
last active administrator cannot be demoted or disabled. Browser requests go
only to same-origin `/api/operators` Route Handlers; the bearer token remains
in the HTTP-only cookie and is forwarded to `/api/v1/auth/*` only by server
code.

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
npm audit --omit=dev
npm run lint
npm run typecheck
npm test
npm run build
npm run smoke:production
```

The production smoke command requires a completed `.next` build. It starts the
compiled dashboard against a local placeholder-only management API, validates
authentication and every enrollment page, exercises token/agent mutations,
and verifies that the one-time token is not rendered again.

Next.js `16.2.12` still declares vulnerable PostCSS and Sharp transitive
versions. `package.json` narrowly overrides only Next's copies to audited exact
versions. Do not remove or broaden those pins until a stable Next.js release
ships patched dependencies and passes this complete check set.

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

## Command console

`/endpoints/{id}/commands` lists an endpoint's signed command history (newest
first, paginated) with a queue admission meter. `operator`/`admin` roles can
dispatch the typed `collect_inventory` operation; `powershell` and `shell`
appear only when the endpoint-detail API reports that the operator's explicit
global, site, or agent script scope matches this endpoint. Admin has no implicit
bypass. `readonly` operators get history and results with an explicit read-only
notice. Dispatch is validated in the browser and again in a
same-origin route handler before being forwarded to the NodeLink API, which
independently enforces role, script scope, trust state, queue admission, and envelope
negotiation. `/endpoints/{id}/commands/{commandId}` shows one command's full
record: lifecycle timestamps, signed payload, envelope evidence (version,
schema, nonce, signing key, signature), exit code, and bounded stdout/stderr
with explicit truncation notes that state the true byte totals; unknown
truncation state from older agents is labeled unknown, never complete.
Commands cannot be cancelled after dispatch — unpicked work dies at its signed
expiry — and in-flight pages re-fetch bounded server data on an interval.
Reading a command record creates a `command_detail.viewed` audit event.

## Operator administration

`/operators` reads `GET /auth/operators` without pagination and renders every
`created_at` timestamp explicitly in UTC. `/operators/new/administrator` and
`/operators/new/technician` are separate entry points backed by the same form;
the displayed product roles map only to `admin` and `operator` in the request.
Creation returns no password and the form drops its one-time password value
after the request. A 409 duplicate email, expired session (401), forbidden role
(403), missing operator/scope target (404), and script-permission conflicts
(409) receive distinct redacted messages.

Script permission is separate from role, including `admin`. `readonly`
operators cannot receive a grant and the UI explains that restriction before
submission. Grant and revoke both require a 3–500 character reason, identify it
as audit-recorded, and require a review step before the same-origin mutation.
Session revocation has its own confirmation and leaves the identity enabled.
Global-role and account-state changes also use compose-then-confirm with a
mandatory 3-500 character audit reason. They invalidate existing sessions, and
moving an identity to Read-only atomically clears any script grant. The API
rejects an attempt to demote or disable the final active administrator.

Known limitations are deliberately omitted from the controls:

- no operator delete endpoint;
- no operator password change or reset endpoint;
- no server-enforced password complexity or forced initial-password rotation;
- no pagination on the operator list.

Administrator-chosen initial passwords without forced rotation are a weakness.
A future change should add a server-backed one-time activation or forced-change
flow, including authorization, an audit event, tests, and documentation, rather
than adding a dashboard-only password-policy claim.

## Foundation boundary

- Dashboard mutations (command dispatch, enrollment control, and operator
  administration) are forwarded same-origin with the operator's HTTP-only
  session cookie; no browser token or persisted dashboard state exists.
  Aggregate overview and audit panels remain fixture-backed.
- The API client makes no automatic retry, and dispatch is not retried —
  a failed dispatch is reported and the operator decides whether to resend.
- Rollback is deployment-level: remove or disable the dashboard service without
  changing the agent, FastAPI server, or database schema.
- The dashboard requires Node.js 24 and a compatible NodeLink API origin; it
  does not change existing agent or server protocol compatibility.

See `../docs/DASHBOARD-DESIGN.md` for the product and interaction design.
