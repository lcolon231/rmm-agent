# NodeLink RMM — Threat Model & Security Design

This document describes the trust boundaries, the mechanisms protecting each, and
the known gaps to close before production use. It is deliberately honest about
what the Phase 1 scaffold does and does not yet do.

## Assets

1. **Endpoint control.** The ability to run commands on client machines is the
   crown jewel. An attacker who can dispatch commands owns every endpoint.
2. **Audit integrity.** For HIPAA-regulated clients, the record of *what was
   done, when, by whom* must be trustworthy. A tamperable log is worse than no
   log because it invites false confidence.
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

**Still to add:** token revocation (JWTs are stateless, so a leaked token is
valid until expiry — consider short lifetimes + refresh tokens, or a
server-side denylist), and rate-limiting on `/auth/login` to slow brute force.

### (2) Server ↔ Network (transport)

Agents connect **outbound only** over TLS. There is no inbound port to open at a
client site — the agent dials the server, never the reverse. This removes the
most common RMM attack surface (exposed agent listeners) and means no firewall
changes at medical offices.

**Before production:** terminate TLS at the server (or a reverse proxy) with a
valid certificate. Consider certificate pinning in the agent for high-assurance
clients.

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

**Known gap — replay within the same agent.** A captured, still-valid command
could in principle be re-presented to the same agent. Mitigations to add: a
per-command nonce the agent records as used, and honoring the server-side TTL
(`expires_at`) agent-side as well. The server already expires commands; the
agent should reject stale ones too.

### (4) Agent → Endpoint OS

The agent runs commands with the privileges of its own process. It can now be
installed as a Windows service (Gate 2), which by default runs as `LocalSystem` —
high privilege — so anyone who can dispatch a verified command has effective
admin on the endpoint, which is why boundary (1) matters so much. Running under a
least-privilege service account is still future work.

- Agent identity is a long-lived bearer token issued at enrollment. The server
  stores only its SHA-256 hash. The plaintext lives in `identity.json` (mode
  0600) on the endpoint.
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

### Toward external verifiability

The local hash chain proves internal consistency but not *when* an event
existed — a sufficiently privileged attacker could in principle rebuild the
entire chain. The design leaves a clean on-ramp to close this: periodically
batch the latest `event_hash` values and anchor a Merkle root to an external,
append-only medium (a managed transparency log, or an on-chain anchor as in the
NodeLink thesis work). Once anchored, no party — including a server operator —
can rewrite history prior to the anchor without detection. The `event_hash`
column is the unit of anchoring; no schema change is needed to add this layer.

## Summary of gaps to close before production

| # | Gap | Severity | Status |
|---|-----|----------|--------|
| 1 | Management API unauthenticated | Critical | **Closed** — operator authN + role-based authZ |
| 2 | No token revocation / login rate-limit | Medium | Open — short-lived tokens + refresh, denylist, throttle |
| 3 | No agent-side command TTL / nonce | High | Open — reject expired commands; per-command nonce |
| 4 | TLS not enforced by scaffold | High | Open — terminate TLS; optional cert pinning |
| 5 | Audit chain not externally anchored | Medium | Open — periodic Merkle anchoring of `event_hash` |
| 6 | Agent runs commands at its own privilege | By design | Partial — installable service (Gate 2) runs as `LocalSystem`; least-privilege service account still open |
| 7 | Agent was foreground-only (no unattended operation) | High | **Closed (Gate 2)** — installable Windows service: auto-start at boot, SCM crash-recovery, rotated file logging, and a network-resilient check-in loop (backoff + jitter) |
