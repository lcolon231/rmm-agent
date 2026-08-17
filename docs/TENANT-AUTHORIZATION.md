# Tenant-scoped authorization (issue #66)

Status: **design / not yet implemented.** This document is the design NodeLink
will build against; it describes a control designed for regulated multi-tenant
operation and is not itself a claim of compliance or completeness.

NodeLink today has **no tenant boundary**. An `Operator` has a global role
(`readonly`/`operator`/`admin`) and can see every client, site, and agent in the
deployment: `GET /clients`, `GET /agents`, and `GET /endpoints` in
`server/app/api/management.py` return all rows and only filter by an *optional*
`client_id` query parameter that the caller supplies and the server never checks.
Internal tracking records this as ENR-013
(`docs/agent-enrollment/open-issues.md`): *"Clients/sites are not authorization
tenants; roles are global … a non-admin operator can access all customers. Add
operator-client memberships and mandatory server-side scoping before calling the
product multi-tenant."*

This issue introduces explicit tenant identity, per-tenant roles, and a
default-deny query boundary, and migrates existing data. It is the root of
Milestone 3: #88 (tenant retention) and #83 (audit portal) depend on it, and
#79/#64 assume tenant identity exists.

## Tenant model

A **tenant is an existing `Client`**. No new top-level entity is introduced; the
`Client → Site → Agent` hierarchy is unchanged. Every agent, command, heartbeat,
audit event, policy, alert, and script run already resolves to exactly one client
through that hierarchy, so the client is a sufficient isolation boundary.

Two authorization concepts are added:

| Concept | Meaning |
|---|---|
| **Platform admin** | A deployment-wide superuser (the MSP owner / you). Sees and administers every tenant, grants and revokes memberships, and bootstraps the first tenant. New column `Operator.is_platform_admin` (default `false`). |
| **Client membership** | A grant of one role over one client. New table `OperatorClientMembership(operator_id, client_id, role, granted_by, reason, created_at)`, unique on `(operator_id, client_id)`. Role is `client_admin` \| `client_operator` \| `client_readonly`, mirroring the existing role tiers, scoped to that client. |

An operator with no membership and `is_platform_admin = false` sees **nothing** —
default deny.

Command *kind* authorization is unchanged: `authorize_command`
(`server/app/core/script_authorization.py`) still decides whether a role may run
a given `CommandKind`, and the existing `script_execution_scope` (site/agent)
still narrows arbitrary-script targets. Tenant membership is an *additional,
outer* gate that decides **which client's agents are reachable at all**. Both must
pass.

## Authorization contract

For any operator action on a resource that resolves to `client_id`:

```
authorized  ==  operator.is_platform_admin
            OR  membership_exists(operator, client_id)
                AND client_role_permits(membership.role, action)
```

Resolution of a resource to its client:

| Resource | Path to client |
|---|---|
| Agent / endpoint | `agent.site_id → site.client_id` |
| Command / shell / remote-desktop launch | `… → agent → site → client` |
| Site | `site.client_id` |
| Audit event | `audit_events.organization_id` (populated with `client_id`) |
| Monitoring policy / maintenance window / patch policy | polymorphic `scope`/`scope_id`, resolved to its client |

**Fail closed as `404`, not `403`.** A resource in another tenant must be
indistinguishable from a non-existent one, so list endpoints omit it and
detail/mutation endpoints return `404` — the same anti-oracle pattern already used
by `_require_owner` in `server/app/api/meshcentral.py`. A `403` is reserved for a
*visible* resource the role may not act on.

States: **authorized** (visible + role permits); **not-found** (cross-tenant or
absent, `404`); **forbidden** (visible but role too low, `403`); **unauthenticated**
(`401`).

## Enforcement

A single module, `server/app/core/tenant_scope.py`, is the one place tenancy is
decided:

- `authorized_client_ids(operator, db) -> set[str] | ALL` — the operator's client
  set, or the `ALL` sentinel for a platform admin.
- `assert_client_visible(operator, client_id, db)` — raise `404` if not visible.
  Used by every detail/mutation/dispatch handler after it resolves the target's
  client.
- `agent_client_filter(operator)` / `client_id_filter(operator)` — a SQLAlchemy
  condition AND-ed into every tenant-scoped read query; a platform admin's filter
  is the always-true clause.

Every operator-facing data path applies one of these: clients, sites,
endpoints/agents, command history and dispatch, audit timeline, monitoring
policies and results, alerts, scheduled tasks, script runs, webhooks, and
remote-desktop launches. The rule is **default-deny**: a new endpoint that forgets
to apply the filter should return nothing, not everything — reviewers treat a
missing filter as a security defect (see the test plan).

Authentication and the JWT are unchanged (`sub`, `gen`, `exp` in
`server/app/core/security.py`). Memberships are read from the database per request
exactly as `role` is today (`get_current_operator` in `server/app/api/deps.py`).
Revocation reuses the existing mechanism: changing a membership or the
platform-admin flag bumps `Operator.token_generation`, immediately invalidating
that operator's outstanding tokens.

## Audit and redaction

- **Anchor every tenant-scoped event to its client.** `audit.record(...)` already
  accepts an `organization_id` parameter that is currently ignored, and
  `AuditEvent` already has an indexed `organization_id` column
  (`server/app/models/models.py`). Thread the resolved `client_id` into
  `organization_id` on all tenant-anchored events.
- **Chain stability.** `organization_id` stays an indexed column and is **not**
  added to the hashed document in `audit._hash_event`, so every existing audit
  chain and anchor still verifies unchanged.
- **New events**, modeled on the existing `operator.script_permission_changed` /
  `_revoked` pair: `operator.tenant_membership_granted`,
  `operator.tenant_membership_revoked`, and `operator.platform_admin_changed`
  (actor, target operator, client, role, mandatory reason). Cross-tenant access
  attempts are audited like `command.authorization_denied`.
- **Redaction.** Register schemas for the new events in `AUDIT_DETAIL_SCHEMAS`
  (`server/app/core/redaction.py`) and add `organization_id`/`client_id` to the
  field lists of tenant-anchored event schemas. The registry already fails closed
  on unknown actions and field drift, so new events must be registered or they are
  rejected.

## Schema and migration

Forward-only Alembic revision `0037_tenant_scoped_authorization.py`, following the
idempotent (`checkfirst=True`) enum/table pattern of
`server/alembic/versions/0036_meshcentral_integration.py`:

1. Create `operator_client_memberships` and the `clientrole` enum; add
   `Operator.is_platform_admin` (default `false`).
2. Add index `audit_events(organization_id, ts, id)` for tenant-filtered timeline
   reads, and the membership uniqueness index.
3. **Backfill `audit_events.organization_id`** from `agent → site → client` where
   an event carries a resolvable `agent_id` (a set-based `UPDATE`, like the
   `ROW_NUMBER` backfill in `0007_audit_sequence.py`). Events with no derivable
   client (system events) keep `NULL`.
4. **Backfill authorization to preserve current access** (recommended): existing
   global `admin` operators become `is_platform_admin = true`; existing
   `operator`/`readonly` operators receive a membership to **every currently
   existing client** with the equivalent `client_role`, recorded as a one-time
   audited migration event. New clients and new operators are default-deny.

   The stricter alternative — promote only the bootstrap admin and require every
   other grant to be re-issued (the default-deny choice made for arbitrary-script
   permission in revision `0010`, see `docs/SCRIPT-AUTHORIZATION.md`) — is
   documented but not chosen, because a silent post-upgrade lockout of every
   non-admin operator is a worse operational failure than a one-time broad grant
   that platform admins can immediately tighten.

## Compatibility, rollout, rollback

- **Additive, forward-only schema** (`docs/ROLLBACK.md`); no agent or protocol
  change — tenancy is enforced entirely at the operator/server boundary.
- **Rollout:** apply `0037`, which backfills access so existing operators keep
  today's visibility; platform admins then tighten memberships. Provide a
  `platform_admin` bootstrap path by extending `scripts/create_admin.py`
  (relevant to ENR-030 first-run setup).
- **Rollback:** migrations are forward-only; recover by restoring a backup at the
  revision or applying a forward fix. Because the JWT is unchanged, reverting the
  server code alone restores global behavior without invalidating sessions.

## Background jobs

System-actor jobs (offline sweep, retention, anchor publish, alert and webhook
senders, scheduled-task dispatch in `server/app/core/tasks.py` and
`scheduler.py`) continue to iterate globally — they act as the system, not as an
operator, so they are not per-operator scoped. Their responsibility under this
design is only to **stamp the resolved `client_id` on the audit events and alerts
they emit**, so that per-tenant evidence exports and retention (#79, #88) can
filter by tenant. The tenant boundary is enforced on operator-initiated reads and
writes.

## Dashboard

The dashboard session and JWT handling are unchanged
(`dashboard/src/lib/dashboard-auth-core.ts`); because the backend filters every
response, the client tree, endpoint views, and audit timeline automatically show
only authorized tenants. A membership-administration API (grant/revoke/list) is in
scope for this issue; a dashboard UI for managing memberships may be delivered
API-first and built out separately.

## Threat model and companion docs

The implementing PR updates:

- `docs/threat-model.md` — the operator→server boundary no longer grants
  deployment-wide visibility; add the cross-tenant IDOR boundary and its tests.
- `docs/ARCHITECTURE.md` — tenant membership in the trust plane.
- `docs/SECURITY-ROADMAP.md` — move #66 to in-progress/implemented.
- `docs/agent-enrollment/open-issues.md` — ENR-013 → In-Progress.
- `docs/SCRIPT-AUTHORIZATION.md` — cross-reference: script scope narrows targets
  *within* a tenant the operator already belongs to.

## Implementation phases

1. **Data model + migration `0037`** — membership table, `is_platform_admin`,
   audit `organization_id` backfill and index.
2. **`tenant_scope` core + read boundary** — the helper module, wired into every
   list/detail read with default-deny and `404` semantics.
3. **Mutations/dispatch boundary** — `assert_client_visible` on all writes and
   command/shell/remote-desktop dispatch; thread `client_id` into `audit.record`;
   add the new membership events and their redaction schemas.
4. **Membership admin API + bootstrap** — grant/revoke/list endpoints (audited,
   reason mandatory) and the `platform_admin` seed path.
5. **Dashboard verification, companion-doc updates, and the full test suite.**

## Test and verification plan

Per the security-change rules in `docs/CONTRIBUTING.md`, using multi-operator /
multi-client fixtures extended from `server/tests/test_administration.py` and
`test_auth.py`:

- **Cross-tenant IDOR (the core requirement):** an operator with membership only
  in Client A receives `404` — not `403`, not data — when reading or acting on
  Client B's sites, agents, endpoints, command history, audit events, monitoring
  policies, alerts, scheduled tasks, script runs, and remote-desktop launches;
  and Client B's rows never appear in any list.
- **Platform admin** sees and administers all tenants.
- **Membership lifecycle** grant/revoke is audited with a mandatory reason and
  bumps `token_generation` so existing tokens for the affected operator are
  rejected.
- **Migration backfill** preserves each existing operator's prior visibility and
  promotes global admins to platform admin; new clients are not auto-granted.
- **Audit anchoring** stamps `organization_id = client_id` on tenant events, the
  hash chain still verifies (`scripts/verify_chain.py`), and no secret leaks into
  details.
- **Background-job outputs** carry `client_id`.
- **PostgreSQL isolation** test (not just SQLite) for the query boundary.

### Mapping to issue #66 acceptance criteria

| #66 acceptance / testing item | Where satisfied |
|---|---|
| Documented contract; valid/invalid/unavailable/unsupported states | *Authorization contract* (states table) |
| Authorized at the API boundary; complete, secret-redacted audit evidence | *Enforcement*, *Audit and redaction* |
| Resource limits, retry/idempotency, compatibility, migration, rollback | *Schema and migration*, *Compatibility, rollout, rollback* |
| Automated tests + reproducible evidence, not aspirational docs | *Test and verification plan* |
| Cross-tenant IDOR/list/filter, background job, export, admin/break-glass, migration, PostgreSQL isolation | *Test and verification plan* (all enumerated) |
| Docs: ARCHITECTURE, threat-model, security-roadmap, runbooks | *Threat model and companion docs* |
