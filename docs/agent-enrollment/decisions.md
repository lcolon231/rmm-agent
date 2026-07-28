# Agent enrollment decisions

## ADR-001: Extend the existing NodeLink architecture

- **Status:** Accepted
- **Date:** 2026-07-27
- **Context:** NodeLink already has FastAPI, SQLAlchemy/Alembic, Pydantic,
  Next.js, Go, JWT role checks, enrollment tokens, agent credentials, and a
  hash-chained audit log.
- **Decision:** Extend those components and the `/api/v1` namespace. Do not add
  another web framework, ORM, identity provider, or audit store.
- **Consequences:** The implementation stays deployable through the current
  workflow. Existing limitations, especially global roles, remain visible
  rather than being hidden behind a second model.

## ADR-002: Use temporary high-entropy enrollment tokens

- **Status:** Accepted
- **Date:** 2026-07-27
- **Context:** Enrollment must not use a permanent shared secret.
- **Decision:** Generate at least 32 random bytes with Python's `secrets`
  module, encode them URL-safely, store only a SHA-256 digest, require expiry,
  default to one use, and return plaintext only from the creation response.
- **Consequences:** Lost plaintext cannot be recovered; administrators must
  revoke and create a replacement. SHA-256 is suitable here because the
  preimage is uniformly random and has at least 256 bits of entropy.

## ADR-003: Redeem tokens transactionally

- **Status:** Accepted
- **Date:** 2026-07-27
- **Context:** A read/check/increment sequence permits concurrent reuse.
- **Decision:** Lock the matching token row on PostgreSQL and perform status,
  expiry, use-limit, and restriction checks plus use-count update, agent
  creation, credential issuance, and success audit in one database
  transaction. Tests on SQLite use a conditional atomic update because SQLite
  ignores row-level `FOR UPDATE`.
- **Consequences:** Single-use semantics remain true under concurrency.
  Enrollment traffic must use the writable primary database.

## ADR-004: Preserve the current bearer credential as an interim agent identity

- **Status:** Accepted (interim)
- **Date:** 2026-07-27
- **Context:** The agent currently persists a per-agent random bearer token and
  the server hashes it. No agent PKI or CA lifecycle exists.
- **Decision:** Keep per-agent bearer credentials for backward-compatible
  delivery, add explicit fingerprint/lifecycle metadata and renewal hooks, and
  do not introduce an unreviewed CA in this change.
- **Consequences:** This is safer than a shared secret but remains vulnerable
  to bearer theft. ADR replacement ENR-001 must define agent-generated keys
  and signed credentials.

## ADR-005: Keep existing role names and enforce permissions on FastAPI

- **Status:** Accepted
- **Date:** 2026-07-27
- **Context:** Existing public contracts use `readonly`, `operator`, and
  `admin`.
- **Decision:** Retain the enum and map it in user documentation:
  `admin` is Super Administrator, `operator` is provisioning administrator,
  and `readonly` is Viewer. FastAPI remains the mandatory authorization
  boundary; frontend checks only improve usability.
- **Consequences:** Public role values do not break. Organization-scoped
  administrators are not complete until operator-client membership exists
  (ENR-013).

## ADR-006: Do not expose permanent deletion

- **Status:** Accepted
- **Date:** 2026-07-27
- **Context:** Token and agent deletion conflicts with incident investigation
  and durable audit evidence.
- **Decision:** Implement revocation and archival semantics only. Do not add
  `DELETE /enrollment-tokens/{id}`.
- **Consequences:** Records remain queryable and auditable. Retention and
  privacy deletion require a separate reviewed policy.

## ADR-007: Preserve and alias the enrollment endpoint

- **Status:** Accepted
- **Date:** 2026-07-27
- **Context:** Existing agents call `POST /api/v1/enroll`; the requested
  contract names `POST /api/agents/enroll`.
- **Decision:** Keep `/api/v1/enroll` and add `/api/v1/agents/enroll` using the
  same handler/service. New fields are additive.
- **Consequences:** Existing agents keep working and new documentation uses the
  resource-oriented path. Security behavior cannot diverge between paths.

## ADR-008: Keep browser secrets server-side

- **Status:** Accepted
- **Date:** 2026-07-27
- **Context:** The dashboard already uses an HTTP-only operator cookie and a
  server-only API client.
- **Decision:** Read operations use authenticated Server Components. Mutations
  use same-origin Route Handlers with the server-held JWT. Plaintext enrollment
  tokens exist only in the in-memory create response and component state, not
  local/session storage, URLs, or analytics.
- **Consequences:** Reloading or leaving the success view permanently removes
  access to the plaintext. Copying is an explicit administrator action.
