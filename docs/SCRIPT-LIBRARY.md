# Versioned script library

Issue #47 adds a technician-facing custody register for reusable PowerShell and
POSIX-shell source. The library stores source; it does not schedule or execute
it. Execution remains independently default-denied by
[`SCRIPT-AUTHORIZATION.md`](SCRIPT-AUTHORIZATION.md). Typed parameters, task
scheduling, and run history belong to issues #48 and #49.

## Data and lifecycle contract

A `script_library_items` row is a stable identity with a case-insensitive
unique name and a pointer to its latest version. `script_versions` is
append-only: every source or metadata change creates the next integer version.
Each version records canonical UTF-8 content, language, SHA-256 digest, byte
count, description, normalized tags, supported platforms, author, and UTC
creation time. `script_version_reviews` allows exactly one final `approved` or
`rejected` decision per version. The absence of a review is `draft`.

Deprecation is terminal and applies to the stable identity. It requires an
administrator, optimistic `record_version`, bounded idempotency key, and reason.
The reason is retained only as SHA-256 and byte-count evidence. A retry with the
same key returns the existing result; a different key or stale version returns
409. Deprecated records remain readable, but cannot receive new versions.
There are no update, delete, unreview, reactivate, or content-overwrite routes.

State meanings are explicit:

- `draft`: valid immutable content awaiting a final review.
- `approved`: a final review accepted this exact digest.
- `rejected`: a final review rejected this exact digest; corrections require a
  new version.
- `deprecated`: the stable script identity is permanently retired; history is
  still available.
- `unavailable`: the record/version does not exist or the API response cannot
  be verified. The dashboard shows no cached substitute.
- `unsupported`: language, platform, tag, control character, line count, or
  content-size validation failed. Unsupported content is never persisted.

## API and authorization

All routes require an authenticated operator:

| Method | Route | Minimum role | Result |
|---|---|---|---|
| `GET` | `/api/v1/script-library` | readonly | bounded paged metadata |
| `POST` | `/api/v1/script-library` | operator | stable item plus draft v1 |
| `GET` | `/api/v1/script-library/{id}` | readonly | metadata and version ledger |
| `GET` | `/api/v1/script-library/{id}/versions/{version}` | readonly | one exact source version |
| `POST` | `/api/v1/script-library/{id}/versions` | operator | next immutable draft |
| `POST` | `/api/v1/script-library/{id}/versions/{version}/review` | admin | final review |
| `POST` | `/api/v1/script-library/{id}/deprecate` | admin | terminal deprecation |

Dashboard mutations pass through same-origin server handlers. Browser code
never receives the bearer token. Readonly users can inspect; operators can
create identities and versions; only admins can review or deprecate. None of
these capabilities changes an operator's separate script-execution scope.

## Validation and resource limits

Content is canonicalized from CRLF/CR to LF and stripped at its outer boundary
before digesting. Empty content, NUL/other unsafe control characters, Unicode
bidi controls, more than 5,000 lines, and more than 57,344 UTF-8 bytes are
rejected. Languages are `powershell` or `shell`. Platforms are a unique subset
of `windows`, `linux`, and `macos`. There are at most 20 unique normalized tags,
using 1-50 characters from `[a-z0-9._-]`. Descriptions are at most 2,000
characters and reasons at most 500.

Configuration bounds the deployment to 1,000 items and 100 versions per item
by default. Lists return at most 100 rows. Version allocation and deprecation
lock the stable item row; database unique constraints are the concurrent-write
backstop. Mutation conflicts are not automatically retried: clients refresh
and resubmit against current evidence. Deprecation alone supports exact
idempotent retry because it is a terminal action.

## Audit and operational evidence

List, item, and source reads are audited. Creation, version append, final
review, and deprecation are audited with actor/user ID, client address, bounded
user agent, IDs, state, counts, platform/tag metadata, and public SHA-256
digests. Raw source, name, descriptions, and reasons never enter audit detail;
free-form names/reasons become digest and byte-count fields through the
fail-closed redaction registry. Operational logs receive only request metadata.

## Migration, deployment, and rollback

Alembic revision `0021` adds the three tables and two PostgreSQL enums. It is
additive and does not change the agent protocol. PostgreSQL enables RLS and
revokes `PUBLIC`, `anon`, and `authenticated`; the direct service database role
remains the owner-managed access path. Deploy the migration before the new API,
then deploy the dashboard. An old server ignores the additive tables, so an
application rollback can keep revision `0021`, but new library writes must be
paused because the old build cannot preserve their workflow.

Alembic downgrade is intentionally unsupported. If schema rollback is required,
restore a tested pre-`0021` backup with the matching old release and explicitly
accept loss of library records created after that recovery point. Prefer a
forward fix. Before rollout, retain a backup; after rollout verify revision
`0021`, readonly retrieval, operator draft creation, admin review, terminal
deprecation retry, digest equality, audit-chain verification, and dashboard
unavailable-state behavior.

Automated evidence lives in `server/tests/test_script_library.py`, migration
coverage in `server/tests/test_migrations.py`, and dashboard parser/authorization
coverage in `dashboard/test/script-library.test.ts`.
