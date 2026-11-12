# Versioned public API

Status: implemented server side (issue #72). This page is the compatibility
promise for integrations: which routes are public, how to authenticate, and
how pagination, idempotency, rate limits, errors, versioning, and deprecation
behave. Webhook payloads have their own catalog in
[`WEBHOOK-EVENTS.md`](WEBHOOK-EVENTS.md).

The machine-readable contract is
[`docs/api/openapi-v1.json`](api/openapi-v1.json) (OpenAPI 3.1). It is
generated from the running code by `server/scripts/export_public_contracts.py`
and compared byte for byte by `server/tests/test_public_api_contract.py`, so
the published document cannot drift from the implementation.

## Public surface

Everything under `/api/v1` is reachable by the dashboard with an operator
session. Only the routes below are the **public v1 contract**. They are the
only routes an API token may call, the only routes in the OpenAPI document, and
the only routes covered by this compatibility policy. The registry in code is
`server/app/core/public_api.py`.

| Route | Stability | Notes |
| --- | --- | --- |
| `GET /api/v1/api-version` | stable | API version, revision, webhook versions, active deprecations |
| `GET /api/v1/endpoints` | stable | Paginated (`page`/`page_size`) |
| `GET /api/v1/endpoints/{endpoint_id}` | stable | |
| `GET /api/v1/endpoints/{endpoint_id}/inventory` | stable | |
| `GET /api/v1/agents/{agent_id}` | stable | |
| `POST /api/v1/agents/{agent_id}/commands` | stable | Signed command dispatch; `Idempotency-Key` |
| `GET /api/v1/agents/{agent_id}/commands` | stable | Paginated (`page`/`page_size`) |
| `GET /api/v1/agents/{agent_id}/commands/{command_id}` | stable | |
| `GET /api/v1/monitoring/alerts` | **beta** | `limit`-bounded; will gain `page`/`page_size` before it becomes stable |
| `GET /api/v1/monitoring/alerts/{alert_id}` | stable | |
| `POST /api/v1/monitoring/alerts/{alert_id}/acknowledge` | stable | Body `request_id` replay and `expected_version` |
| `POST /api/v1/monitoring/alerts/{alert_id}/resolve` | stable | Body `request_id` replay and `expected_version` |

**Stable** routes follow the deprecation policy below. **Beta** routes are
supported, but their shape may change between revisions. Each change is
listed in the release notes.

Command dispatch through the public API keeps every existing gate: role and
script-execution scope, approval policy, emergency overrides, maintenance
windows, the outstanding-command limit, and the signed command envelope. An
API token only ever narrows those gates.

## Authentication

Send `Authorization: Bearer <credential>`. The credential is either:

- **An API token (`nlk_...`)**, the credential for integrations. It is
  tenant-scoped, has a role ceiling, always expires, and works only on the
  public routes above.
- **An operator session JWT**, what the dashboard uses. It is short-lived and
  bound to an interactive login. It works on the public routes too, but it is
  not intended for unattended integrations.

### API tokens

An operator mints a token for themselves. The token acts *as that operator*,
but as a narrowed principal:

| Property | Rule |
| --- | --- |
| Tenant | Exactly one client, which must be one the owner belongs to. A platform-admin owner may pick any client but the token is still confined to it. A token never crosses the tenant boundary. |
| Global role | `min(owner role, role_ceiling)`. Default ceiling: `readonly`. |
| Client role | `min(owner's membership role, client_role_ceiling)`. Default ceiling: `client_readonly`. |
| Routes | Public routes only. Any other route returns `401`. |
| Never permitted | Step-up and MFA-gated operations, platform-admin operations, and token, session, operator, or membership management (`403 api_token_not_permitted`, or `401` off the public surface). |
| Lifetime | Mandatory expiry, default `API_TOKEN_DEFAULT_TTL_DAYS` (30) and at most `API_TOKEN_MAX_TTL_DAYS` (90). |
| Dies when | Revoked, expired, owner disabled, owner logout-all or any membership change (`token_generation` bump), or the bound membership removed. Takes effect on the next request. |
| Storage | SHA-256 only. The plaintext is returned once, at creation. |

Token management is dashboard-session only and is **not** part of the public
surface. A leaked token therefore cannot mint successors.

| Route | Who | Behaviour |
| --- | --- | --- |
| `POST /api/v1/api-tokens` | Any operator, **step-up required** | Body `{name, client_id, role_ceiling?, client_role_ceiling?, expires_in_days?}`. `201` with `token` (once). `404` if the client is not visible. `422` if a ceiling exceeds your role or the TTL exceeds the maximum. `409 api_token_limit_reached` beyond `API_TOKEN_MAX_ACTIVE_PER_OPERATOR` (20). |
| `GET /api/v1/api-tokens` | Owner; a platform admin may pass `operator_id` | Metadata only (`prefix`, ceilings, `last_used_at`, `active`). Never the secret. |
| `DELETE /api/v1/api-tokens/{id}` | Owner or platform admin | Idempotent revoke. Not step-up gated, so a leak can be contained in one click. |

All token refusals at authentication time return the same
`401 {"detail": "Invalid or expired token"}`. A caller cannot tell an unknown
token from a revoked, expired, orphaned, or out-of-scope one.

## Tenant model

Tenancy is the issue #66 model ([`TENANT-AUTHORIZATION.md`](TENANT-AUTHORIZATION.md)).
A resource in a client you cannot see returns **`404`**, the same as a missing
one. A resource you can see but whose client role is too low returns
**`403`**. API tokens are enforced inside the same helpers
(`server/app/core/tenant_scope.py`), so every public route inherits the
boundary rather than re-implementing it.

## Pagination

The v1 contract for list routes is page-based:

- Query: `page` (integer ≥ 1, default 1) and `page_size` (1 to 100; the
  default is per route and recorded in the OpenAPI document).
- Response: `{ "items": [...], "page": n, "page_size": n, "total": n }`,
  plus any route-specific summary fields.
- Ordering is stable within a route, newest first unless the route documents
  a `sort` parameter. A page beyond the end returns an empty `items`.
- `total` is exact at query time. Rows written between page requests can shift
  page boundaries. Use the resource's own timestamps for reconciliation.

`test_public_api_contract.py` enforces this shape on every stable list route.

## Idempotency

| Route type | Mechanism |
| --- | --- |
| `POST .../commands` | Optional **`Idempotency-Key`** header, 1 to 128 printable ASCII characters |
| Alert acknowledge/resolve | Required body `request_id` (16 to 64 `[A-Za-z0-9_-]`); repeating it replays the result |
| `GET` | Naturally idempotent |

`Idempotency-Key` behaviour, per principal (API token, or operator for JWT
sessions):

| Situation | Result |
| --- | --- |
| No header | Every request is a new attempt (unchanged behaviour) |
| First use | Processed. The key is reserved *in the same transaction* as the side effect, so a refusal or crash leaves nothing reserved and you can retry. |
| Same key, same method, path, and body, completed | The original status and body are replayed with `Idempotent-Replayed: true`. No second command is queued. |
| Same key, different request | `422 idempotency_key_reused` |
| Same key, first request still in flight | `409 idempotency_in_progress`. Retry after a short delay. |
| Malformed key | `400 idempotency_key_invalid` |
| Older than `IDEMPOTENCY_KEY_TTL_HOURS` (24) | Forgotten; the key may be reused. Expired keys are pruned by the retention sweeper. |

Use a fresh random key (for example a UUID) per logical operation, and reuse
it only for retries of that same operation.

## Rate limits

Each API token has two sliding 60-second budgets:
`PUBLIC_API_RATE_LIMIT_PER_MINUTE` (120) for all requests, and
`PUBLIC_API_MUTATING_RATE_LIMIT_PER_MINUTE` (30) for non-`GET` requests.
Mutating requests count against both. Exceeding a budget returns:

```text
HTTP/1.1 429 Too Many Requests
Retry-After: 12
RateLimit-Limit: 120
RateLimit-Remaining: 0
RateLimit-Reset: 12

{"detail": {"code": "rate_limited", "message": "..."}}
```

Back off for at least `Retry-After` seconds. Limits are enforced per server
process, the same caveat as the login limiter
([`DEPLOYMENT-READINESS.md`](DEPLOYMENT-READINESS.md)), so behind *N* workers
the effective ceiling is up to *N* times higher. Dashboard (JWT) traffic is not
subject to these budgets.

## Errors

Every error body is `{"detail": ...}`, where `detail` is one of:

- a string, for simple not-found and permission failures;
- an object with a stable `code` and a human `message` (`step_up_required`,
  `rate_limited`, `idempotency_key_reused`, `alert_version_conflict`, ...);
- a list, for request validation (`422`).

**Branch on HTTP status and `code`, never on `message` text.** Codes are part
of the contract: within v1 an existing code keeps its meaning, and new codes
may be added. Common statuses:

| Status | Meaning |
| --- | --- |
| `400` | Malformed header (e.g. `idempotency_key_invalid`) |
| `401` | Missing, invalid, expired, or revoked credential, or a token used off the public surface |
| `403` | Visible but not permitted: role or client-role ceiling, or `api_token_not_permitted` |
| `404` | Not found **or not in your tenant** |
| `409` | State or version conflict, idempotency in progress, or an outstanding-command or token limit |
| `422` | Validation failure, or an idempotency key reused for a different request |
| `429` | Rate limited (see above) |
| `503` | Dependency unavailable; safe to retry with backoff |

## Versioning and compatibility

- **Major version in the path.** `/api/v1`. A breaking change to a stable
  route ships as `/api/v2` alongside v1, never in place.
- **Revision date.** Each additive change to the public surface (a new route,
  or a new optional field or parameter) bumps `API_REVISION`. Every public
  response carries it as `NodeLink-API-Version: 2026-11-12`, and
  `GET /api/v1/api-version` returns it.
- **Additive within v1.** New response fields, new optional parameters, new
  error codes, and new enum values may appear at any revision. Clients
  **must ignore unknown fields** and treat unknown enum values as "other".
- **Breaking** means: removing or renaming a route, field, or parameter;
  making an optional input required; changing a type or a meaning; or
  tightening a validation that accepted input before.
  `test_no_breaking_change_to_stable_operations` refuses these against the
  committed OpenAPI baseline.

### Deprecation policy

1. A stable route or field to be removed is marked deprecated in the registry
   with a `deprecated_on` date and a `sunset_on` date **at least 180 days
   later**. A test enforces the minimum.
2. From `deprecated_on`, responses carry `Deprecation: @<epoch>` (RFC 9745),
   `Sunset: <HTTP-date>` (RFC 8594), and
   `Link: </docs/PUBLIC-API.md#deprecation-policy>; rel="deprecation"`. The
   OpenAPI operation is marked `deprecated: true`, the release notes announce
   it, and `GET /api/v1/api-version` lists it.
3. The route keeps working unchanged until `sunset_on`. Removal happens only
   in a release after that date.

Security fixes are the one exception. A change needed to close a
vulnerability may tighten behaviour immediately. It is called out in the
release notes and the security advisory.

## OpenAPI and SDK expectations

- NodeLink does **not** ship an official SDK. Generate a client from
  [`docs/api/openapi-v1.json`](api/openapi-v1.json) with any OpenAPI 3.1
  generator. The document lists only public routes, declares the `bearerAuth`
  scheme, and annotates each operation with `x-nodelink-stability`,
  `x-nodelink-pagination`, and `x-nodelink-idempotency`.
- Generated clients should send `Idempotency-Key` on command dispatch, honour
  `Retry-After` on `429` and `503`, and tolerate unknown fields and enum values.
- Pin the OpenAPI file from the release you integrate against. The file in
  each tagged release is the contract for that release.
- The live `/docs`, `/redoc`, and `/openapi.json` endpoints are development
  aids. They are **off in production** unless `EXPOSE_OPENAPI=true`. They
  describe the whole internal surface, not the public contract.

## States at a glance

| State | Behaviour |
| --- | --- |
| Valid token, public route, in tenant, within ceilings and budget | Served; audit rows attribute `operator [api_token:<id>]` |
| Valid token, non-public route | `401` |
| Valid token, resource in another tenant | `404` |
| Valid token, action above a ceiling | `403` |
| Valid token, step-up or MFA-gated operation | `403 api_token_not_permitted` |
| Revoked, expired, or orphaned token, or disabled owner | `401` |
| Over budget | `429` with `Retry-After` |
| Idempotent replay | Original response plus `Idempotent-Replayed: true` |
| Unsupported API major (e.g. `/api/v2`) | `404` (no such route) |
| Deprecated route before sunset | Served with `Deprecation`/`Sunset`/`Link` headers |

## Audit, redaction, and observability

- `api_token.created` and `api_token.revoked` are hash-chained audit events
  ([`AUDIT-EVENTS.md`](AUDIT-EVENTS.md)). They store the token id, display
  prefix, owner, client, ceilings, and expiry, plus a SHA-256 digest of the
  name. The secret and its hash never enter the log.
- Every audit event produced *through* a token (for example
  `command.dispatched`) records the actor as `<operator> [api_token:<id>]`,
  so the tamper-evident log answers which credential acted, not just whose.
  This uses the existing `actor` field, with no audit schema change.
- `last_used_at` (minute resolution) shows token liveness in
  `GET /api/v1/api-tokens`. Every request is in the structured `http.request`
  log with its request id. Per-request token use is not audited, which keeps
  the chain free of read noise.

## Schema and migration

Migration `0051` adds `api_tokens` and `api_idempotency_keys`. It is additive
and forward-only, like every NodeLink migration. Both tables start empty and
are never read by an older server build, so the migration is safe to apply
ahead of the build and safe to leave applied after a rollback.

## Compatibility, rollout, and rollback

- **Mixed versions.** The dashboard keeps using operator JWTs and needs no
  change. Agents are unaffected. API tokens are opt-in: nothing changes until
  an operator mints one.
- **Behaviour changes for existing clients.** Public responses gain
  `NodeLink-API-Version`. `POST .../commands` accepts an optional
  `Idempotency-Key`. Production stops serving `/docs`, `/redoc`, and
  `/openapi.json` unless `EXPOSE_OPENAPI=true`. Alert email and webhook
  delivery history and retry are now tenant-scoped (previously any readonly
  operator could read them, and any operator could retry them, across tenants).
- **Rollout.** Deploy the migration, deploy the server, mint one
  `readonly`/`client_readonly` token for a pilot integration, confirm
  `GET /api/v1/api-version` and a list call work, then widen.
- **Rollback.** Revoke the tokens (`DELETE /api/v1/api-tokens/{id}`), or bump
  an owner's `token_generation` with logout-all. An older server build ignores
  the new tables, and the `nlk_` bearer then fails JWT decoding with `401`.

## Threat model notes

New trust boundary: an unattended bearer credential. Mitigations are listed
in [`threat-model.md`](threat-model.md): tenant confinement, role ceilings,
public-route allowlist, mandatory expiry, hash-only storage, step-up to mint,
no token-mints-token, one-click revoke, generation-based kill switch,
per-token budgets, and token-attributed audit.

## Verification

| Area | Test |
| --- | --- |
| Token lifecycle, ceilings, tenant isolation, kill switches, route allowlist, audit, redaction | `server/tests/test_api_tokens.py` |
| Idempotency replay, conflicts, expiry, and pruning; command-dispatch dedupe | `server/tests/test_idempotency.py` |
| Committed OpenAPI current; pagination, idempotency, and error contract; breaking-change gate; deprecation headers; production docs gating | `server/tests/test_public_api_contract.py` |
| Webhook catalog, schema, and signed vectors; docs coverage | `server/tests/test_webhook_catalog.py`, `server/tests/test_contract_schemas.py` |
| Delivery history and retry tenant isolation | `server/tests/test_webhook_endpoint_api.py` |
| Migration 0051 | `server/tests/test_migrations.py` |

## Mapping to issue #72 acceptance criteria

- **Contract and states documented:** this page, the states table,
  [`WEBHOOK-EVENTS.md`](WEBHOOK-EVENTS.md), and the committed OpenAPI and
  JSON Schema.
- **Authorized at the API boundary, with redacted audit:** a token principal
  is resolved in `get_current_operator` and confined by `tenant_scope`. Token
  lifecycle events are registered in the fail-closed audit policy, and actions
  taken through a token are attributed to it.
- **Limits, idempotency, compatibility, migration, rollback:** per-token
  budgets, `Idempotency-Key`, the breaking-change gate, additive migration
  0051, and the rollback steps above.
- **Objective tests:** the verification table above.

## Known v1 boundaries

- No dashboard UI for token management yet. Use the API from an authenticated
  dashboard session, or a script holding a session JWT. This is a follow-up.
- Rate limits are per process, not cluster-wide.
- `GET /api/v1/monitoring/alerts` is beta until it adopts page-based
  pagination.
- Webhook destinations remain deployment-level administrator configuration,
  not per-tenant.
