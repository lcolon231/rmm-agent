# Versioned script library

Issues #47 and #48 add a technician-facing custody register for reusable
PowerShell and POSIX-shell source plus immutable typed parameter definitions
and encrypted, expiring per-run value preparation. The library still does not
schedule or execute scripts. Execution remains independently default-denied by
[`SCRIPT-AUTHORIZATION.md`](SCRIPT-AUTHORIZATION.md); recurring dispatch and run
history belong to issue #49.

## Data and lifecycle contract

A `script_library_items` row is a stable identity with a case-insensitive
unique name and a pointer to its latest version. `script_versions` is
append-only: every source or metadata change creates the next integer version.
Each version records canonical UTF-8 content, language, SHA-256 digest, byte
count, description, normalized tags, supported platforms, author, and UTC
creation time. `script_version_reviews` allows exactly one final `approved` or
`rejected` decision per version. The absence of a review is `draft`.

`script_parameter_definitions` stores an ordered set of at most 32 definitions
for one immutable version. A definition change therefore requires a new script
version and a new review. `script_parameter_value_sets` stores one entire
resolved value document as AES-256-GCM ciphertext, bound by authenticated data
to its script-version and value-set IDs. It also stores only safe operational
metadata: provided/defaulted/secret key names, a keyed HMAC-SHA256 fingerprint,
creator, request ID, and expiry. Raw values do not have a read API.

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
  content-size validation failed, or a future parameter kind/language cannot be
  rendered. Unsupported content is never persisted.
- `invalid`: a definition violates its type contract, a required per-run value
  is missing, a value has the wrong JSON type or violates its bound/choice, or
  an unknown key is supplied. Nothing is persisted.
- `available`: an approved, non-deprecated version has an encrypted value set
  that has not reached its UTC expiry.
- `expired`: the value set remains immutable evidence but must not be consumed.
  Retrying the same request ID returns that expired state, not a fresh lifetime.

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
| `POST` | `/api/v1/script-library/{id}/versions/{version}/parameter-value-sets` | operator | encrypted values for a future run |
| `POST` | `/api/v1/script-library/{id}/deprecate` | admin | terminal deprecation |

Dashboard mutations pass through same-origin server handlers. Browser code
never receives the bearer token. Readonly users can inspect; operators can
create identities and versions; only admins can review or deprecate. None of
these capabilities changes an operator's separate script-execution scope.
Value preparation additionally requires an approved, non-deprecated exact
version. Readonly users cannot submit values, and no endpoint decrypts or
returns a value set to a browser.

## Typed parameter contract

Keys use `^[A-Za-z][A-Za-z0-9_]{0,63}$` and are unique ignoring case. Labels
are 1-100 characters and descriptions at most 500. Supported kinds are:

| Kind | JSON value | Validation/default contract |
|---|---|---|
| `string` | string | optional 0-16,384 character minimum/maximum; typed default allowed |
| `number` | finite JSON number | optional finite inclusive minimum/maximum; typed default allowed; booleans are rejected |
| `boolean` | JSON boolean | no bounds; boolean default allowed |
| `choice` | string | 1-50 unique choices, each 1-200 characters and 4,096 bytes total; default must be a choice |
| `secret` | string | string length bounds; defaults are forbidden |

A definition with a default cannot also be required. At preparation time,
explicit values win, then defaults are applied, required missing keys fail, and
optional missing keys are omitted. Strings are never coerced to numbers or
booleans. The canonical resolved JSON document is limited to 32,768 UTF-8 bytes.

Scripts reference generated variables rather than interpolation tokens:
`$NL_PARAM_Key` in PowerShell and `$NL_PARAM_Key` in POSIX shell. Internal
server and agent helpers quote single-quoted literals, emit native PowerShell
booleans/numbers, export shell values, and never rewrite placeholders inside
source. Agent output redaction replaces exact declared secret values
longest-first. This execution helper is deliberately inactive for legacy
`command` schema v1: issue #49 must negotiate a parameter-aware dispatch
contract and must not persist plaintext secrets in the existing command JSON.

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

Parameter preparation is bounded to 32 definitions/values, 32,768 canonical
bytes, a 24-hour lifetime, and 10,000 simultaneously unexpired value sets per
script version by default. `request_id` is the idempotency boundary: the same
ID and keyed value fingerprint returns the original set; the same ID with
different values returns 409. An expired set retried under its original ID
reports `expired` rather than receiving a fresh lifetime, and no longer occupies
the per-version active budget. Invalid/unsupported inputs are not retried.
Missing/malformed encryption configuration — an absent, wrongly encoded, or
wrong-length key — returns 503 with `parameter_encryption_unavailable` and fails
closed: no value set is written and no audit event claims success. Because the
fingerprint is HMAC-keyed with the same key, rotating it turns in-flight retries
into 409 conflicts, so rotate only when no prepared set is still consumable.

Ciphertext is bound by AES-GCM authenticated data to its script-version and
value-set IDs, so a value set copied onto another version or ID, or decrypted
with a different key, fails authentication instead of yielding values.

## Audit and operational evidence

List, item, and source reads are audited. Creation, version append, final
review, and deprecation are audited with actor/user ID, client address, bounded
user agent, IDs, state, counts, platform/tag metadata, and public SHA-256
digests. Raw source, name, descriptions, and reasons never enter audit detail;
free-form names/reasons become digest and byte-count fields through the
fail-closed redaction registry. Operational logs receive only request metadata.
Value preparation adds the value-set/request IDs, safe key lists, keyed
fingerprint, and expiry. It never adds plaintext/default/secret values. The
encrypted document and encryption key are never audit fields.

## Migration, deployment, and rollback

Alembic revision `0021` adds the library custody tables; revision `0022` adds
parameter definitions, encrypted value sets, and the parameter-kind enum. Both
are additive. PostgreSQL enables RLS and
revokes `PUBLIC`, `anon`, and `authenticated`; the direct service database role
remains the owner-managed access path. Deploy the migration before the new API,
set a stable, separately generated `SCRIPT_PARAMETER_ENCRYPTION_KEY`, then
deploy server and dashboard. The current signed-command protocol is unchanged;
the agent helper is dormant until a future negotiated schema uses it. An old
server ignores the additive tables, so an application rollback can keep
revision `0022`, but all library and value-preparation writes must be paused.

Alembic downgrade is intentionally unsupported. If schema rollback is required,
restore a tested backup from before the target revision with the matching old
release and explicitly accept loss of later library definitions/value sets.
Before a component rollback, retain the failed-state database and encryption
key until every value set is expired or safely invalidated. Prefer a forward
fix. After rollout verify revision `0022`, definition round trips, invalid and
missing/default/choice cases, secret ciphertext/decryption in a controlled test,
idempotent preparation/conflict, expiry, audit-chain verification, and that no
API/dashboard/audit/log evidence contains a submitted secret.

## Known limitations

- **Expired ciphertext is retained, not pruned.** Expiry is enforced on read:
  an expired set reports `expired` and cannot be consumed, but its
  `encrypted_values` column is never cleared. `core/retention.py` does not
  target `script_parameter_value_sets`, so encrypted secret documents
  accumulate for the life of the database. Until a pruner exists, treat the
  encryption key as long-lived key material and destroy it only together with
  the rows it protects. Adding a sweep that clears `encrypted_values` while
  preserving the metadata evidence — the same shape as aged command output —
  is the intended follow-up.
- **No consumption path.** Nothing decrypts a value set yet; `decrypt_values`
  has no production caller. Issue #49 must negotiate a parameter-aware dispatch
  schema before values reach an endpoint, and must not place plaintext in the
  existing `commands.payload`.
- **Redaction is exact-substring only.** The agent helper removes declared
  secret values verbatim from captured output. A script that encodes, hashes,
  splits, or otherwise transforms a secret before printing it defeats that, as
  does a secret straddling the stream truncation cap.
- **Definitions are immutable but not garbage-collected.** Both new tables use
  `ondelete="RESTRICT"`, so a script version can never be deleted while its
  parameter rows exist. This is deliberate for custody, and it means storage
  only grows.

Automated evidence lives in `server/tests/test_script_library.py`, migration
coverage in `server/tests/test_migrations.py`, and dashboard parser/authorization
coverage in `dashboard/test/script-library.test.ts`. Cross-platform quoting,
tamper failure, and redaction are covered by `server/tests/test_script_parameters.py`
and `agent/internal/executor/parameters_test.go`.
