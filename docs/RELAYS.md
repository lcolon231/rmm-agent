# Multi-region relays (issue #87)

This document defines the control-plane and agent contract for routing agent
traffic through regional relays. It covers the trust model, every accepted and
refused state, the data-residency boundary, operations, rollout, and rollback.

## Status

| Piece | State |
|---|---|
| Relay registry, key lifecycle, tenant residency policy (server) | Implemented |
| Signed relay forwarding: verification, skew, store-and-forward age, body, replay bounds (server) | Implemented |
| Signed routing manifest and route-change audit (server) | Implemented |
| Manifest verification, relay failover with origin fallback, relay-safe key handling (agent) | Implemented |
| Contracts and shared vectors (`contracts/routing-manifest-v1`, `contracts/relay-forward-v1`) | Implemented |
| **Deployable relay service** (the process that sits in a region and forwards) | **Not implemented.** Depends on #84 (shared rate limiting / workers) and #85 (HA). |
| Storage residency (regional databases) | **Not implemented, not claimed.** See [Residency boundary](#residency-boundary). |

Do not describe NodeLink as having multi-region relays in production until a
relay service exists and the verification in this document has been run
against it.

## Trust model

A relay is a regional HTTPS ingress operated by the deployment. It is
**authenticated, but never trusted for content**.

- **Relay → control plane.** Every forwarded request carries the
  `X-NodeLink-Relay-*` headers (see
  [`contracts/relay-forward-v1.schema.json`](../contracts/relay-forward-v1.schema.json)).
  The relay signs, with its own Ed25519 key, the newline-joined fields
  `nodelink-relay-forward-v1`, relay id, key id, method, path (with query),
  SHA-256 of the exact body, timestamp, queued-at, and nonce. Only the public
  key is registered with the control plane.
- **Agent → control plane through a relay.** The agent's own bearer credential
  still authenticates the agent on every request. A relay cannot act as an
  agent it does not hold a credential for. Because a relay terminates TLS, it
  does see that credential in transit (exactly like the origin's TLS
  terminator does), which is why relay registration and key changes require a
  platform administrator with a fresh step-up.
- **Commands** remain end-to-end signed by the control-plane keyring
  (command-v3) and verified on the endpoint. A relay cannot mint, alter, or
  replay a command: the agent's signature, expiry, nonce, and journal checks
  are transport-independent.
- **Routes and command keys** reach an agent only inside a **routing
  manifest** the control plane signs with *every* signing-capable keyring key
  (see [`contracts/routing-manifest-v1.schema.json`](../contracts/routing-manifest-v1.schema.json)).
  The agent verifies the exact bytes (`nodelink-agent-routing-v1:` prefix) with
  a key it already trusts, checks the agent id, expiry (max 24 h lifetime), and
  that `issued_at` is not older than the manifest it holds (rollback
  protection). Signing with every key means an agent mid-rotation verifies the
  manifest that introduces the incoming key using the outgoing one.
- **Unsigned key bundles.** A heartbeat that came through a relay never
  changes the agent's trusted command keys unless the change is inside a
  verified manifest. A direct origin heartbeat keeps the pre-relay behavior
  (unsigned `command_public_keys` honored) for compatibility.
- **Origin-only endpoints.** Enrollment, credential reattachment, interactive
  shell, support chat, and self-update reports are never routed through a
  relay, and the server refuses them with `relay_route_unsupported` if a relay
  tries. A support-chat launch URL that arrives on a relayed heartbeat is
  ignored, because it would open a browser on the user's desktop.

### Known limitation

Fields of the heartbeat response other than commands, keys, and routes
(`monitoring_checks`, `inventory_requested`, `trust_state`) are not
end-to-end signed. A relay is trusted for their integrity in the same way the
origin's TLS terminator is. A compromised relay could suppress or alter
monitoring assignments for agents that route through it. It cannot execute
anything: every command still needs a keyring signature. Signing these fields
is tracked as follow-up work, not claimed here.

## Residency boundary

Residency in this release is **ingress residency**: which region's relays
may carry a tenant's agent traffic. The control-plane database is a single
deployment and is **not** partitioned by region. A tenant whose contract
requires data at rest to stay in a region is not served by this feature
alone.

| Policy mode | Relays in the home region | Relays in other regions | Direct origin |
|---|---|---|---|
| none (no policy) | Allowed | Allowed | Allowed |
| `preferred` | Allowed, listed first | Allowed, listed after | Allowed, listed last |
| `strict` | Allowed, only these are listed | **Refused** `relay_region_mismatch` | **Refused** `residency_route_required` for agents advertising `relay-routing`; allowed for older agents |

The older-agent carve-out exists so that enabling a strict policy never
strands a mixed fleet. `GET /clients/{id}/region-policy` reports
`legacy_direct_agents` so the gap is visible until those endpoints upgrade.
Origin-only endpoints (shell, support chat, self-update reports) are never
refused for arriving direct, because they have no relayed path. A strict
policy can only be set when the home region is `active` and has at least one
`active` relay (`409 region_has_no_active_relay`).

## Contract

### States

| Object | States | Notes |
|---|---|---|
| Region | `active` → `draining` ↔ `active`; any → `disabled`; `disabled` → `active` | `draining` keeps accepting forwards but drops out of new manifests; `disabled` refuses forwards (`relay_region_disabled`). |
| Relay | `pending` → `active` ↔ `draining`; any → `revoked` (terminal) | Activation needs a live, unexpired key (`relay_has_no_key`). `draining` accepts forwards but is not offered in new manifests. Revocation revokes every key. |
| Relay key | `active` → `retired` / `revoked` | At most two live keys per relay (current plus staged successor). `not_after` is required and at most 400 days out. A public key is never reused, even after retirement. |
| Tenant policy | none, `preferred`, `strict` | Set/cleared by a platform admin with step-up; readable by anyone who can see the tenant. |

### Forward refusals (server)

All refusals are fail-closed, return `{"detail": {"code": ...}}`, and happen
before any route handler runs.

| Code | HTTP | Meaning | Audited |
|---|---|---|---|
| `relay_routing_disabled` | 403 | Relay headers present while `RELAY_ROUTING_ENABLED=false` | No (metric) |
| `relay_headers_incomplete` / `relay_headers_invalid` | 400 | Missing or malformed header | No (metric) |
| `relay_unknown` | 403 | No such relay | No (metric) |
| `relay_route_unsupported` | 403 | Endpoint is origin-only | Yes |
| `relay_not_active` | 403 | Relay `pending` or `revoked` | Yes |
| `relay_region_disabled` | 403 | Region `disabled` | Yes |
| `relay_body_too_large` | 413 | Body over `RELAY_MAX_FORWARD_BODY_BYTES` | Yes |
| `relay_key_unknown` / `relay_key_inactive` / `relay_key_expired` | 403 | Key not registered for this relay, retired/revoked, or past `not_after` | Yes |
| `relay_signature_invalid` | 403 | Signature does not cover these exact bytes | Yes |
| `relay_clock_skew` | 403 | Signed timestamp outside `RELAY_CLOCK_SKEW_SECONDS`, or queued-at after timestamp | Yes |
| `relay_forward_too_old` | 403 | Held longer than `RELAY_MAX_FORWARD_AGE_SECONDS` (store-and-forward bound) | Yes |
| `relay_replay` | 409 | (relay, nonce) already accepted | Yes |
| `relay_region_mismatch` | 403 | Strict tenant, relay in another region | Yes |
| `residency_route_required` | 403 | Strict tenant, relay-capable agent came direct | No (metric) |

Unauthenticated noise (unknown relay id, malformed headers, feature disabled)
is counted in `relay_forward_refused_total` but never audited, so a stranger
cannot fill the audit chain. Refusals by a registered relay are audited as
`relay.forward_refused`, at most once per (relay, reason) per minute, with
`suppressed_count` carrying the number folded into that row.

### Replay and idempotency

The server records a `relay_forward_receipts` row, unique on
(relay_id, nonce), and **commits it before the handler runs**. A replay is
refused even if the original request's handler failed. Under concurrency the
unique index decides: exactly one of two simultaneous forwards with the same
nonce is accepted (PostgreSQL race test). Agent-level idempotency is
unchanged. Results are idempotent by command id, so an agent that fails over
mid-upload and retries through another route is safe.

Receipts are pruned after `RELAY_RECEIPT_RETENTION_DAYS` (minimum 1 day,
default 7). That is always far beyond the accepted skew plus forward-age
window, so pruning never reopens a replay.

### Agent failover

- Routed endpoints: heartbeat, command result, inventory, monitoring results,
  credential renewal.
- Order: manifest relays in order, skipping any in cooldown; then the origin.
  The origin is always the last resort, even in strict mode. If the server
  refuses it, nothing is lost, and when the operator relaxes the policy the
  agent recovers on its own.
- Fail over on: transport errors (DNS, TLS, SPKI pin mismatch, reset), 5xx,
  429, and `relay_*` / `residency_*` refusal codes.
- Never fail over on: 401 (credential handling stays with the existing
  reattach path), or ordinary 4xx request errors.
- Cooldown: 30 s doubling to 10 min per failing relay, kept across manifest
  refreshes, reset on success.
- Each relay has its own TLS SPKI pins from the manifest. The configured
  `tls_spki_pins` continue to apply to the origin only.
- An expired manifest (TTL `RELAY_ROUTE_MANIFEST_TTL_SECONDS`, default 1 h)
  drops every relay. The agent is back to plain origin polling until the next
  manifest arrives.

## Audit continuity

| Action | When |
|---|---|
| `relay_region.created`, `relay_region.status_changed` | Region administration |
| `relay.registered`, `relay.status_changed` | Relay administration |
| `relay.key_registered`, `relay.key_retired`, `relay.key_revoked` | Key lifecycle (reason stored as digest) |
| `tenant.region_policy_set` | Policy set or cleared (with previous values) |
| `relay.forward_refused` | Registered relay's forward refused (rate-limited) |
| `agent.route_changed` | The **server-observed** ingress path of an agent's accepted heartbeat changed (relay id or `origin`), once per change |

Every event goes through the single hash-chained audit log, so relay activity
cannot reorder or gap the sequence. Path changes are recorded from what the
server verified, not from what an agent claims. Field lists are in
[`AUDIT-EVENTS.md`](AUDIT-EVENTS.md).

## Configuration

| Setting | Default | Bounds | Meaning |
|---|---|---|---|
| `RELAY_ROUTING_ENABLED` | `false` | | Master switch. Off: relay headers refused, no manifests, no residency enforcement. |
| `RELAY_CLOCK_SKEW_SECONDS` | 120 | 5–600 | Accepted relay clock skew |
| `RELAY_MAX_FORWARD_AGE_SECONDS` | 300 | 10–3600 | Store-and-forward bound |
| `RELAY_MAX_FORWARD_BODY_BYTES` | 1 MiB | 4 KiB–8 MiB | Forwarded body bound (buffered before any DB work) |
| `RELAY_ROUTE_MANIFEST_TTL_SECONDS` | 3600 | 300–86400 | Manifest lifetime |
| `RELAY_MAX_ROUTES` | 8 | 1–16 | Relays per manifest (origin excluded) |
| `RELAY_RECEIPT_RETENTION_DAYS` | 7 | 1–365 | Replay-guard retention |

In production, enabling relay routing with a keyring that has no
signing-capable active/overlap key refuses startup.

## API

All under `/api/v1`. Every route requires a platform administrator except the
policy read.

| Method | Path | Notes |
|---|---|---|
| GET / POST | `/relay-regions` | Create: `{code, name}`, code `^[a-z0-9-]{2,32}$` |
| PATCH | `/relay-regions/{id}` | `{status}` |
| GET / POST | `/relays` | Register: `{region_id, name, base_url, tls_spki_pins}`. `base_url` must be a bare `https://host[:port]`. Starts `pending`. |
| GET / PATCH | `/relays/{id}` | `{status}`; `revoked` requires step-up |
| POST | `/relays/{id}/keys` | Step-up. `{key_id, public_key_pem, not_after}` |
| POST | `/relays/{id}/keys/{key_id}/retire` | |
| POST | `/relays/{id}/keys/{key_id}/revoke` | Step-up. `{reason}` |
| GET | `/clients/{id}/region-policy` | Any operator who can see the tenant |
| PUT / DELETE | `/clients/{id}/region-policy` | Step-up. `{region_id, mode}` |

## Rollout

1. Apply migration `0048` (additive; inert until enabled).
2. Upgrade agents. Agents advertising `relay-routing` behave exactly as
   before until a manifest arrives.
3. Set `RELAY_ROUTING_ENABLED=true`. Every relay-capable agent now receives a
   manifest containing only the origin, because no relay is active yet.
4. Create regions, register relays and their keys, then activate the relays.
5. Optionally set tenant policies: `preferred` first, `strict` only after
   `legacy_direct_agents` reaches zero, if older agents must not use the
   origin.

## Rollback and recovery

- **Disable**: set `RELAY_ROUTING_ENABLED=false`. Relay headers are refused,
  so agents' relayed calls fail over to the origin immediately. No manifest is
  issued, stored manifests lapse within one TTL, and residency is not
  enforced. No data change is needed.
- **Compromised relay key**: revoke the key (or the whole relay) with step-up.
  Forwards signed by it are refused from the next request. Agents fail over
  to the next route.
- **Stranded strict tenant** (every home relay down): clear the policy or
  switch it to `preferred`. Agents always try the origin last and pick up the
  new manifest on their next beat.
- **Schema**: forward-only. Crossing below `0048` requires the exact-revision
  restore procedure in [`ROLLBACK.md`](ROLLBACK.md).

## Verification

Run these automatically in CI:

- `server/tests/test_relays.py`
  - authorization
  - lifecycle
  - every refusal code
  - store-and-forward age bound
  - replay
  - strict, preferred and cross-tenant residency
  - the legacy-agent carve-out
  - manifest order, cap and rotation signatures
  - route-change audit
  - audit chain integrity and sequence continuity
  - receipt retention
  - a PostgreSQL race test that two same-nonce forwards accept exactly one
- `server/tests/test_relay_vectors.py`, `test_contract_schemas.py`: the server encoding matches the committed vectors and schemas.
- `server/tests/test_migrations.py`: 0048 is additive and forward-only.
- `agent/internal/verify/manifest_test.go`: the shared vectors, plus untrusted signer, legacy key and expiry.
- `agent/internal/client/routes_test.go`
  - failover order
  - partition, cooldown and recovery
  - 401 and 4xx do not fail over
  - an expired manifest means origin only
  - origin-only endpoints never use a relay
- `agent/internal/service/relay_routing_test.go`
  - a relay-injected unsigned key bundle is ignored
  - signed rotation
  - rollback and forged manifests are refused
  - persistence
