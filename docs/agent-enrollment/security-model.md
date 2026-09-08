# Agent enrollment security model

## Trust boundaries

```text
Administrator browser
  | same-origin cookie; no browser bearer-token storage
  v
Next.js server boundary
  | operator JWT, server-to-server
  v
FastAPI authorization + enrollment transaction
  | SQLAlchemy transaction
  v
PostgreSQL primary

Installer/agent -- HTTPS + temporary token --> FastAPI
Enrolled agent -- HTTPS + per-agent credential --> FastAPI
```

The reverse proxy owns TLS termination. PostgreSQL, signing keys, dashboard
runtime, and FastAPI are trusted deployment components. The endpoint and
installer environment are untrusted until enrollment succeeds; hostname,
agent name, OS, architecture, environment, and public-key fields are claims.

## Enrollment-token lifecycle

1. An `operator` or `admin` creates a token for one site.
2. The server obtains 32 random bytes from `secrets.token_urlsafe`, prefixed by
   `nlenr_` for recognition. Entropy remains at least 256 bits.
3. The create response returns plaintext exactly once.
4. The database stores SHA-256 digest and a short non-secret display prefix.
5. Tokens require a future expiration, default to one use, and are capped by
   deployment policy.
6. Redemption validates revocation, expiry, use count, site/environment/name/
   hostname restrictions, then consumes a use.
7. Exhausted tokens report `Used`; time-expired tokens report `Expired`.
8. Revocation is retained; permanent delete is not exposed.

SHA-256 is appropriate for a uniformly random 256-bit token. Password-style
slow hashing is unnecessary and would make online redemption more expensive
without increasing the already infeasible preimage search.

## Atomic single-use enforcement

PostgreSQL redemption obtains a row lock and also executes a conditional update
requiring:

- not revoked;
- `revoked_at IS NULL`;
- expiration in the future;
- `use_count < max_uses`.

Use count, last-used time, agent creation, credential issuance, and success
audit append share the request transaction. SQLite tests use the conditional
update because SQLite ignores `FOR UPDATE`. Enrollment must target the writable
primary in HA designs.

## Agent credential lifecycle

Successful redemption generates an independent random per-agent bearer
credential. The database stores:

- SHA-256 authentication verifier;
- a domain-separated SHA-256 administrative fingerprint;
- issuance time and optional expiry;
- revocation/trust state.

The plaintext is returned only in enrollment or renewal response and persisted
by the agent's protected identity layer. It is never shared across agents.

Bearer credentials remain an interim architecture decision. They have a finite
configured lifetime and the agent normally rotates at the midpoint. Rotation
keeps the just-superseded bearer in a short overlap slot, allowing a lost
response or failed local persist to retry before the agent adopts the new token.

An active endpoint powered off across expiry can use a dedicated bounded
reattach endpoint while its expired bearer still matches the current token
slot. The default window is 30 days, is configurable down to zero, and has a
one-year configuration ceiling. Ordinary endpoints continue to reject the
expired bearer. Reattach rotates immediately, uses the same response-loss
overlap, and is audited as `agent.credential_reattached`, distinct from
enrollment and routine `agent.credential_renewed` events.

The bearer is still the endpoint's only proof of possession; command public
keys in `identity.json` belong to the server and cannot authenticate the
endpoint. A future agent-generated private key with server-signed short-lived
credentials would strengthen this boundary, but is not part of bounded
reattach.

## Revocation and rotation

Token revocation prevents future redemption but does not affect agents already
issued unique credentials. Agent revocation makes its credential authenticate
the same as an unknown credential and expires outstanding commands.

Renewal and reattach replace the stored verifier atomically and retain the held
bearer only for the short response-loss overlap. Revoked agents authenticate
identically to unknown credentials. Quarantined agents may continue their
existing bare-heartbeat behavior while a credential is valid, but cannot obtain
a credential through reattach. Unknown, outside-window, quarantined, revoked,
and overlapped-out reattach attempts all return the same `401 Invalid agent
token`; the endpoint is not a credential-state oracle.

## Rate limiting

Enrollment applies a sliding-window source-IP limiter. Default:

- 10 attempts;
- 60-second window;
- `429` plus `Retry-After` when blocked.

Successful enrollment clears the source counter so controlled rollouts are not
penalized. Failures remain. State is process-local; multiple workers multiply
the effective limit. A shared limiter is required before multi-worker/HA
production.

Forwarded addresses are trusted only when `TRUST_PROXY_HEADERS=true` and the
application port is reachable exclusively from the trusted proxy.

## Audit and redaction

Recorded events include token creation/revocation, enrollment success/failure,
credential renewal/reattachment, and agent revocation. Query columns are duplicated into
hash-bound event detail so changing actor/token/organization/source references
breaks verification.

Never recorded:

- plaintext enrollment token or digest;
- agent credential or authentication verifier;
- private keys;
- public-key bodies;
- administrator notes;
- complete enrollment request bodies.

Logs and errors use generic external enrollment failure messages. Internal
failure categories are permitted in protected audit events for incident
analysis. The process metrics endpoint exposes counters only.

## Browser security and CSRF posture

The browser receives only an HTTP-only, SameSite=Lax operator session. Backend
FastAPI role checks are mandatory. Same-origin mutation handlers validate the
`Origin` header and send JSON to FastAPI. Plaintext token state exists only in
the creation component's memory and is discarded on navigation/reload.

No token is placed in URL parameters, local/session storage, analytics, or
client-visible configuration.

## Threat model

| Threat | Control | Residual risk |
|---|---|---|
| Database disclosure | Enrollment/agent plaintext not stored | Agent verifier hashes still require protection against direct DB modification |
| Token interception | HTTPS, short expiry, limited use, restrictions | Compromised installer can use the token before intended installer |
| Concurrent token replay | Row lock + conditional atomic update | HA must use primary-consistent redemption |
| Token guessing | 256-bit entropy, rate limiting | Rate limiter is process-local |
| Rogue metadata claims | Optional exact restrictions | No device attestation |
| Browser token leakage | One-time in-memory display; no URLs/storage | Browser/administrator workstation compromise can capture creation response |
| Stolen agent bearer | Unique credential, DPAPI/permissions, revocation | No proof-of-possession; non-Windows storage is file-permission only |
| Privilege escalation in UI | FastAPI role enforcement | Roles are global, not tenant-scoped |
| Log/trace leakage | Allowlisted structured audit and generic errors | Future instrumentation must preserve redaction |
| Audit tampering | Hash chain, sequence, external anchors | Anchors protect only when immutable publication is configured |
| Denial of enrollment | Source limiter, bounded validation | Distributed abuse needs upstream WAF/shared controls |

## Known residual risks

See `open-issues.md`. The highest-priority residual risks are:

- global roles and no tenant membership;
- bearer credentials without independent device proof-of-possession;
- process-local rate limiting/metrics;
- unsupported native keychain on Linux/macOS;
- unsigned Windows installer;
- no device attestation or duplicate-hostname identity policy;
- bounded reattach still treats possession of the endpoint bearer as possession
  of the enrolled identity;
- operational TLS/backup/anchor configuration remains administrator-owned.
