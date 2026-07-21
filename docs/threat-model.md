# NodeLink RMM — Threat Model & Security Design

This document describes the trust boundaries, the mechanisms protecting each, and
the known gaps to close before production use. It is deliberately honest about
what the Phase 1 scaffold does and does not yet do.

## Assets

1. **Endpoint control.** The ability to run commands on client machines is the
   crown jewel. An attacker who can dispatch commands owns every endpoint.
2. **Audit integrity.** For customers in regulated environments, the record of
   *what was done, when, by whom* must be trustworthy. A tamperable log is worse
   than no log because it invites false confidence.
3. **Telemetry / inventory.** Lower sensitivity, but leaks host and network
   detail useful to an attacker.

## Trust boundaries

```
   Operator ──(1)── Server ──(2)── Network ──(3)── Agent ──(4)── Endpoint OS
```

### (1) Operator → Server

**Status: IMPLEMENTED.** The management API is gated behind operator
authentication and role-based authorization:

- **AuthN.** `POST /auth/login` verifies an email + bcrypt-hashed password and
  returns a signed JWT. `get_current_operator` validates that token on every
  management request. Missing/invalid tokens return 401.
- **AuthZ.** Three roles (`readonly` < `operator` < `admin`). The management
  router requires `readonly` at minimum (nothing is anonymous); mutating routes
  require `operator`; operator management requires `admin`. Insufficient role
  returns 403.
- **Accountability.** The acting operator's email is recorded as the `actor` on
  each `command.dispatched` audit event.
- **Bootstrap.** The first admin is created out-of-band via
  `scripts/create_admin.py` (the create-operator endpoint is admin-only, so it
  can't mint the first admin itself).

Login hardening: unknown-email and wrong-password both return an identical 401,
and a dummy hash verification runs on unknown emails to avoid a timing
side-channel that would reveal which accounts exist.

Two hardening layers on top of that:

- **Token revocation.** JWTs are stateless, so individual tokens cannot be
  recalled — instead each operator row carries a `token_generation` counter,
  every JWT records the generation it was minted under, and validation rejects
  any mismatch. `POST /auth/revoke-tokens` (self) or
  `POST /auth/operators/{id}/revoke-tokens` (admin) bumps the counter,
  instantly invalidating all outstanding tokens for that operator. Both are
  audited (`operator.tokens_revoked`).
- **Login rate-limiting.** Failed logins are counted per (client IP, email) in
  a sliding window; once it fills, `/auth/login` answers 429 with Retry-After,
  even for the correct password. A successful login clears the pair's counter.
  Keying on the pair slows online brute force without letting an attacker lock
  a victim out from a different address. The counters are in-process — behind
  multiple workers the effective limit multiplies by the worker count; move
  them to a shared store before scaling out.

### (2) Server ↔ Network (transport)

Agents connect **outbound only**. There is no inbound agent port to open at a
client site: the agent dials the server, never the reverse. The client accepts
both HTTP and HTTPS URLs today, so TLS is a deployment requirement rather than
an application-enforced invariant.

**Before production:** terminate TLS at the server (or a reverse proxy) with a
valid certificate — the supported pattern (Caddy in front of uvicorn bound to
localhost) is documented in `docs/DEPLOYMENT-TLS.md` with `deploy/Caddyfile`.
Consider certificate pinning in the agent for high-assurance clients.

### (3) Network → Agent (command authenticity)

This is the mechanism that lets the audit log mean something. Every command is
signed by the server's **Ed25519 private key**. The agent receives the matching
public key at enrollment and verifies the signature over a canonical encoding of
`{command_id, agent_id, kind, payload}` before executing anything. A command
that fails verification is refused and never run.

Consequences:

- A man-in-the-middle who breaks TLS still cannot forge a command without the
  signing key.
- A compromised *transport* cannot inject endpoint commands.
- The signature binds the command to a specific `agent_id`, so a valid command
  for one endpoint cannot be replayed against another.

**Replay within the same agent — now mitigated.** A captured, still-valid
command could in principle be re-presented to the same agent. The agent now
defends against this on two fronts:

- **Signed time window.** `command-v3` binds canonical `issued_at` and
  `expires_at` into the signature. The agent rejects malformed, expired,
  overlong, or implausibly future-dated windows.
- **Replay store.** The agent persists command IDs and signed nonces
  (`seen_commands.json`, mode 0600, beside `identity.json`, written atomically)
  and reserves both before execution. Entries whose expiry has lapsed are
  pruned; a duplicate command ID is silently ignored while a duplicate nonce is
  reported as a refusal.

Refusal order in the agent is signature → time window → command-ID replay →
nonce replay → execute.

**Version downgrade — mitigated.** The signed `command-v3` bytes include
`envelope_version`. Agents advertise versions during enrollment and heartbeat;
the server withholds dispatch until `command-v3` is reported. Missing, unknown,
and legacy versions fail closed before signature verification. Python and Go
consume the same positive and negative vectors. Existing queued commands are
expired during migration because their legacy signatures do not cover the v2
contract.

**Key lifecycle.** Command-v3 binds a signing-key ID and the agent only trusts
the active/overlap public-key bundle delivered by the server. Rotation is an
operator-run workflow (`scripts/rotate_command_key.py`, `docs/KEY-ROTATION.md`):
a new key is staged as `overlap` so the fleet learns its public key before it
signs, promoted to `active` while the outgoing key steps down to `overlap` so
its in-flight commands still verify, and `retired` only once nothing it signed
is still in flight. Compromise skips the waits (generate + activate + retire
immediately, deliberately refusing the compromised key's in-flight commands),
and rollback re-activates the previous key while it remains `overlap`. Every
mutation is written atomically and appended to a rotation journal, and the full
lifecycle is rehearsed in tests.

### (4) Agent → Endpoint OS

The agent runs commands with the privileges of its own process. It can now be
installed as a Windows service (Gate 2), which by default runs as `LocalSystem` —
high privilege — so anyone who can dispatch a verified command has effective
admin on the endpoint, which is why boundary (1) matters so much. Running under a
least-privilege service account is still future work.

- Agent identity is a long-lived bearer token issued at enrollment. The server
  stores only its SHA-256 hash. On the endpoint the token lives in
  `identity.json` inside a versioned envelope: DPAPI-encrypted (user scope,
  under the enrolling account — LocalSystem for the installed service) with a
  protected SYSTEM+Administrators-only DACL on Windows; protection `none` with
  mode 0600 elsewhere. Legacy plaintext files are migrated atomically on first
  load, and protection failures refuse to run rather than fall back to
  plaintext. Server-side, operators can quarantine (reversible, operator role)
  or revoke (terminal, admin role) an agent; revoked tokens fail
  authentication with the same response as unknown tokens.
- Enrollment tokens are one-time (configurable `max_uses`), can expire, and can
  be revoked. They are shown in plaintext only once, at creation.

## Audit log: tamper-evidence

Every meaningful action appends an `AuditEvent` to a **hash chain**: each event
stores `prev_hash` (the previous event's hash) and `event_hash` (the SHA-256 of
this event's canonical content, including `prev_hash`). Because each event
commits to its predecessor, altering or deleting any event breaks the chain from
that point forward.

`GET /api/v1/audit/verify` walks the chain and returns the first broken event, if
any. This is demonstrated by a test that mutates one field of one row and
confirms detection.

### External verifiability: Merkle anchoring

The local hash chain proves internal consistency but not *when* an event
existed — a sufficiently privileged attacker could rebuild the entire chain
consistently and the chain check alone would pass. The anchoring layer closes
this:

- `POST /api/v1/audit/anchors` (operator+) computes a **Merkle root** over the
  `event_hash` values of every event in the chain (in ascending `seq` order;
  the legacy prefix's `seq` was frozen from the historical `(ts, id)` order by
  migration 0007) and stores it as an `AuditAnchor` covering that prefix. The
  act of anchoring is itself audited (`audit.anchored`).
- `GET /api/v1/audit/anchors/{id}/verify` recomputes the root over the covered
  prefix and compares — any alteration, removal, or reordering of covered
  events is detected, **including a fully consistent chain rebuild** (this is
  demonstrated by a test that rebuilds the chain and shows the chain check
  passing while the anchor check fails).
- The Merkle construction is documented in `app/core/anchor.py` so an external
  verifier can reimplement it: leaves are hex-decoded `event_hash` values;
  levels pair left-to-right with SHA-256(left‖right); an unpaired node is
  carried up unchanged; a single leaf is its own root.

**The root must leave the building.** An anchor row in the same database
proves nothing against an attacker who owns that database — they can rebuild
anchors too. A scheduled publisher (`app/core/anchor_publish.py`, issue #76)
carries each anchor's Merkle root to an external immutable destination and
records a tamper-evident receipt. Two backends ship: an S3-compatible bucket
with Object Lock (COMPLIANCE mode — un-deletable until its retention date, even
by the account root) and an append-only filesystem/WORM directory. Publication
is idempotent (content-addressed keys), retried on outage, and lag past a
threshold alerts. Credentials never enter a receipt. A standalone verifier
(`scripts/verify_anchor_receipt.py`) recomputes the root from read-only event
hashes and the artifact downloaded from the destination, so history can be
validated without trusting — or writing to — the NodeLink database. Publication
is opt-in (the operator chooses and operates the destination) and logs a loud
warning in production when unconfigured. See `docs/AUDIT-ANCHORING.md`.

## Summary of gaps to close before production

| # | Gap | Severity | Status |
|---|-----|----------|--------|
| 1 | Management API unauthenticated | Critical | **Closed** — operator authN + role-based authZ |
| 2 | No token revocation / login rate-limit | Medium | **Closed** — per-operator `token_generation` bump revokes all outstanding JWTs (self + admin endpoints, audited); sliding-window 429 throttle on `/auth/login` per (IP, email). Limiter is per-process — use a shared store when running multiple workers |
| 3 | Command expiry/version/nonce are not signed | Critical | **Closed** — `command-v3` binds schema version, issued-at, expiry, nonce, and signing-key ID with shared Go/Python verification; staged key rotation/compromise/rollback are operator-run and rehearsed (`scripts/rotate_command_key.py`, `docs/KEY-ROTATION.md`) |
| 4 | TLS not enforced by scaffold | High | **Mostly closed** — ENVIRONMENT=production fails startup on debug mode, placeholder/short SECRET_KEY, missing signing keys, or a missing/non-HTTPS/loopback PUBLIC_BASE_URL; X-Forwarded-For is ignored unless TRUST_PROXY_HEADERS is explicitly enabled (rightmost entry only). Deployment path documented (`docs/DEPLOYMENT-TLS.md`, `deploy/Caddyfile`); certificate lifecycle monitoring and agent cert pinning still open |
| 5 | Audit chain not externally anchored | Medium | **Mostly closed** — a scheduled publisher writes each anchor's Merkle root to an external immutable destination (S3 Object Lock or a WORM filesystem) with tamper-evident receipts, idempotent retry, lag alerting, and a clean-room verifier. Publication is opt-in (loud when unconfigured); the operator still chooses and operates the destination |
| 6 | Agent runs commands at its own privilege | By design | Partial — installable service (Gate 2) runs as `LocalSystem`; least-privilege service account still open |
| 7 | Agent was foreground-only (no unattended operation) | High | **Closed (Gate 2)** — installable Windows service: auto-start at boot, SCM crash-recovery, rotated file logging, and a network-resilient check-in loop (backoff + jitter) |
| 8 | No agent revocation/quarantine or DPAPI credential protection | Critical | **Mostly closed** — explicit active/quarantined/revoked trust states with reasoned, audited operator transitions; revoked credentials fail auth without an oracle and outstanding work is expired; quarantined agents get bare acks only; identity is DPAPI-protected with a restricted DACL on Windows (envelope-versioned, atomic plaintext migration, no plaintext fallback). Windows service/installer lifecycle automation for these paths remains with issue #23 |
| 9 | Command stdout/stderr and queue policy are unbounded | High | **Closed** — stdout/stderr are capped (256 KiB each, 384 KiB combined, excess counted not buffered) with deterministic UTF-8-safe truncation recorded in command and audit data; dispatch payloads are capped at 64 KiB; per-agent outstanding-command admission (configurable, refuses at dispatch) and a per-heartbeat FIFO batch cap bound queue depth, with the agent executing one command at a time |
| 10 | Audit ordering is not monotonic and anchors remain local | High | **Closed** — every event carries a unique monotonic seq assigned under a serialized append (advisory lock + unique constraint) and bound into its hash; verification/anchoring walk seq order and detect gaps/reorders; anchors are published to external immutable storage with receipts and clean-room verification (`docs/AUDIT-ANCHORING.md`) |
| 11 | No production migrations, automated restore, or rollback rehearsal | High | **Mostly closed** — Alembic migrations with startup revision guard; encrypted streaming backups with manifests and off-host upload hook; isolated restore with checksum, schema, chain, and anchor validation, rehearsed in CI (`docs/BACKUP-RESTORE.md`). Production-schedule evidence and a release rollback drill (#26) remain |
| 12 | Windows artifacts are unsigned and release evidence lacks SBOM/provenance | High | Partial — releases publish an SPDX SBOM (Go + Python), signed SLSA build-provenance attestations, and checksums for every artifact; Authenticode signing remains open (needs a paid certificate) |
| 13 | Client/site records are not authorization tenants | High | Open — roles and management access are global |
