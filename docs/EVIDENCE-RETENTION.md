# Immutable evidence storage, retention enforcement, and legal hold (issue #81)

Status: **design only — not implemented.** This document defines the contract
before the code exists, the way `docs/TENANT-AUTHORIZATION.md` did for issue
#66. Nothing described here may be cited as an existing control until the
as-built section at the end says it shipped and the tests named in the
verification plan pass. This describes a control designed for regulated
operation; it is not itself a claim of compliance.

## What exists today, and the exact gap

Three pieces are already built and this issue does not redesign them:

| Built | Where | Behavior |
|---|---|---|
| Merkle anchors published to WORM | `server/app/core/anchor_publish.py` | Anchor roots are written to a filesystem directory or an S3 bucket with Object Lock (`ObjectLockMode` + `ObjectLockRetainUntilDate`), and an `AnchorPublication` row stores a credential-free receipt plus `receipt_sha256`. |
| Deterministic evidence documents | `server/app/core/evidence_bundles.py` | Versioned canonical JSON / normalized CSV for one tenant over a pinned audit prefix. |
| Signed evidence packages | `server/app/core/evidence_packages.py` | Tagged PDF and a domain-separated Ed25519-signed deterministic ZIP whose manifest binds every member by path, media type, size, and digest. |
| Audit-safe pruning | `server/app/core/retention.py` | Prunes heartbeats and clears aged command output. It physically does not target `AuditEvent`, `AuditAnchor`, or `AnchorPublication`. |

The gap is narrow and specific:

1. **A package is never stored.** `GET /api/v1/evidence/bundles/export?format=zip`
   builds the archive in memory and streams it to the caller
   (`server/app/api/evidence.py`). Nothing writes it anywhere. The signed bytes
   an auditor was handed exist only in that auditor's download folder — NodeLink
   cannot later prove what it produced, and `evidence_packages.py` says so in
   its own `VERIFY.txt`: verification "does not independently prove that an
   external WORM destination still retains a receipt."
2. **Retention is per-data-class, not per-artifact.** `retention.py` bounds
   telemetry and command output by age. There is no notion of an artifact that
   must be *kept* for a minimum period, as opposed to one that may be dropped
   after a maximum period.
3. **There is no hold concept at all.** Nothing can suspend a deletion, and
   nothing records why a deletion was suspended or by whom.

This issue closes those three, and nothing else. Tenant-specific retention
*policy* is #88 and depends on this; the standalone verification CLI is #82 and
also depends on this.

## Model

Three new concepts. The tenant boundary is the existing `Client`, per #66.

| Concept | Meaning |
|---|---|
| **Evidence artifact** | One durably recorded export. Identified by its existing `package_id` (signed ZIP) or `bundle_id`, and bound to the exact bytes by `content_sha256`. Carries the tenant, the pinned audit range, the storage location, and a lifecycle state. New table `EvidenceArtifact`. |
| **Retention rule** | The minimum period an artifact must be kept, resolved when the artifact is created and then frozen onto the row. A deployment default plus an optional per-tenant override (the override is where #88 later plugs in). Frozen, not resolved at deletion time, so shortening a policy tomorrow cannot retroactively expose yesterday's artifact to deletion. |
| **Legal hold** | A named, reasoned, operator-created suspension of deletion over a scope (one artifact, one tenant, or global). While any hold covers an artifact, no automated or manual deletion may proceed. Artifact- and tenant-scoped holds may be open-ended; a **global hold must carry an expiry** (see below). New table `EvidenceLegalHold`. |

### Lifecycle states

An artifact is always in exactly one state, and the state is derived from
stored facts rather than being independently writable:

| State | Meaning | Deletable |
|---|---|---|
| `pending` | The row exists; the object has not yet been confirmed at the destination. | no |
| `stored` | The destination confirmed the write and a receipt is recorded. | no (retention not expired) |
| `failed` | The destination rejected the write after the bounded retry budget. The row and its error are kept as operational evidence. | no |
| `expired` | `retain_until` has passed and no hold covers the artifact. | yes |
| `held` | At least one active hold covers the artifact, regardless of `retain_until`. | no |
| `deleted` | The object was removed after a legal deletion decision. The row survives with its digests, so the export remains provable-to-have-existed. | — |

`held` outranks `expired`: a hold placed after expiry but before the pruner runs
still blocks deletion. The pruner re-evaluates hold coverage inside the same
transaction as the delete, so a hold created concurrently cannot be raced.

### Bounded global holds

A `global` hold freezes every tenant's artifacts at once, including tenants
created after it was placed. That reach is occasionally exactly right and is
also the easiest thing in this design to leave switched on by accident, so it is
the one scope that **must** carry an `expires_at`:

- `artifact` and `tenant` holds may be open-ended, matching how a legal hold
  actually works — it lasts until counsel releases it.
- `global` holds are rejected without an expiry
  (`400 evidence_hold_expiry_required`), and the expiry is bounded by
  `evidence_global_hold_max_days` (default 365).
- A global hold that needs to outlive its expiry is **renewed by creating a new
  hold**, not by extending the old one. An expired hold stops covering anything
  and is never silently revived, so the register reads as a sequence of dated
  decisions rather than one indefinite flag.

An expired hold and a released hold both stop covering artifacts; they are
distinguished in the register (`expired` vs `released`) because "counsel let it
lapse" and "counsel released it" are different facts.

## Storage contract

Reuse the existing backend interface rather than inventing a second one. The
`FilesystemBackend` / `S3Backend` pair in `anchor_publish.py` already has the
right shape (`object_key`, `publish`, credential-free `PublishResult`), and it
already fails closed when an existing object at a content-addressed key differs
from what is being written.

The change is to lift that pair out of `anchor_publish.py` into a shared
`app/core/immutable_store.py` that both anchors and evidence artifacts use,
keeping the anchor call sites byte-identical in behavior. This is a refactor
with no functional change to anchor publication, and it is a separate,
reviewable phase (see phases below).

- **Key**: content-addressed and deterministic, mirroring the anchor scheme —
  `evidence/{tenant_id}/{created:%Y/%m}/package-{package_id}-{content_sha256}.zip`.
  A retry after a crash rewrites identical bytes at the same key instead of
  forking; a differing object at that key is a WORM violation and fails closed.
- **Object Lock**: written with `ObjectLockMode` and an
  `ObjectLockRetainUntilDate` equal to the artifact's frozen `retain_until`.
  `COMPLIANCE` mode is the default, matching `anchor_s3_object_lock_mode`.
- **Receipt**: the same credential-free shape as anchor receipts (bucket, key,
  version-id, ETag, sha256, lock mode, retain-until), hashed into
  `receipt_sha256` so a later edit of the stored receipt is detectable. **No
  access keys and no presigned URLs, ever** — this is the existing rule in
  `anchor_publish.py` and it is not relaxed here.
- **Filesystem backend**: unchanged in character — an append-only directory with
  best-effort `0444`, where real immutability is the operator's WORM mount. It
  stays the CI test vehicle.

### When an artifact is created

Storing every ad-hoc export would turn a readonly operator's curiosity into
unbounded WORM spend. Storage is therefore **opt-in per request and bounded**:

- `GET /evidence/bundles/export` gains `&retain=true`. Without it, behavior is
  exactly as today — build, stream, audit, store nothing.
- `retain=true` requires the tenant-scoped `client_admin` role (or platform
  admin), not the `readonly` floor the export itself uses. Retaining is an
  administrative act with cost and legal consequence; reading is not.
- Only `format=zip` may be retained. The PDF is unsigned and the JSON/CSV are
  reproducible from a pinned `through_seq`; the signed ZIP is the only artifact
  whose authenticity is self-contained, so it is the only one worth immutable
  bytes.
- A per-tenant daily cap (`evidence_retain_daily_limit`, default 24) fails
  closed with `429 evidence_retain_rate_limited`.
- Storage is **synchronous within the request** and failure is visible: if the
  destination rejects the write, the caller gets `503 evidence_store_unavailable`
  and the row is `failed`. A caller must never be told an artifact was retained
  when it was not. The bytes are still returned on the success path, so the
  operator has their download and NodeLink has its copy of the same digest.

## API contract

All routes are tenant-scoped through the existing `assert_client_visible` /
`assert_client_action` helpers, so an operator with no membership sees nothing.

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/evidence/artifacts` | tenant `client_readonly` | List stored artifacts for one tenant: id, package/bundle id, digests, state, `retain_until`, covering holds, destination URI. Never returns content. |
| GET | `/evidence/artifacts/{id}` | tenant `client_readonly` | One artifact, plus receipt verification (`verified` / `mismatch` / `unknown`, never a bare boolean). |
| GET | `/evidence/artifacts/{id}/content` | tenant `client_admin` | Re-download the stored bytes from the destination, digest-checked against `content_sha256` before a byte is returned. A mismatch is `409 evidence_artifact_corrupt`, not a silent pass-through. |
| POST | `/evidence/legal-holds` | platform admin | Create a hold: scope (`artifact`/`tenant`/`global`), scope id, name, mandatory reason, and an expiry that is optional for `artifact`/`tenant` and **mandatory for `global`**. |
| GET | `/evidence/legal-holds` | tenant `client_readonly` (scoped) / platform admin (all) | List holds and what each currently covers. |
| POST | `/evidence/legal-holds/{id}/release` | platform admin | Release a hold with a mandatory reason. Terminal and idempotent — a released hold never returns to active; re-holding creates a new row, so the history reads as a sequence of decisions rather than a toggled flag. |
| DELETE | `/evidence/artifacts/{id}` | platform admin | Explicit deletion of an `expired` artifact with a mandatory reason. Refuses while held (`409 evidence_artifact_held`) or before expiry (`409 evidence_retention_active`). |

Failure states follow the existing convention (`valid` / `invalid` /
`unavailable` / `unsupported`) already used by `EvidencePackageError`:

| State | Condition | Response |
|---|---|---|
| unsupported | immutable store not configured | `409 evidence_store_disabled` |
| unsupported | `retain=true` with `format != zip` | `400 evidence_retain_unsupported_format` |
| invalid | hold scope id does not resolve | `404` (anti-oracle, same as tenant 404) |
| invalid | `global` hold without an expiry, or beyond the maximum | `400 evidence_hold_expiry_required` |
| invalid | delete while held or before expiry | `409` as above |
| unavailable | destination unreachable / rejected | `503 evidence_store_unavailable` |
| invalid | stored bytes fail their digest | `409 evidence_artifact_corrupt` |

## Retention enforcement

A new `evidence_retention_sweeper` loop in `server/app/core/tasks.py`, modeled
directly on `retention_sweeper`, running on its own interval.

Each pass, in one transaction per artifact:

1. Select artifacts where `state = 'stored'` and `retain_until <= now`.
2. Re-check hold coverage **inside the transaction**. Any covering hold →
   record `state = 'held'` and skip.
3. Otherwise transition `stored → expired`. **Expiry alone never deletes.**

Deletion of expired artifacts is a separate, explicitly enabled step
(`evidence_auto_delete_expired`, default **false**). The default deployment
accumulates expired artifacts and reports them, because silently destroying
compliance evidence by default is the wrong failure mode; an operator who wants
automatic deletion opts in. When enabled, deletion still refuses while any hold
covers the artifact, and the row survives in `deleted` state with its digests
intact.

Two invariants the sweeper cannot violate, enforced the same way `retention.py`
enforces its own — by construction, not by care:

- It never targets `AuditEvent`, `AuditAnchor`, or `AnchorPublication`. Those
  remain never-pruned.
- It never deletes an object whose `retain_until` is in the future. Under S3
  Object Lock in `COMPLIANCE` mode the destination would refuse anyway; the
  server refuses first so behavior is identical on a filesystem mount that
  cannot enforce it.

`storage_status` gains an `evidence` class: artifact counts by state, oldest
expired-but-undeleted age, active hold count, failed-store count, and a
threshold flag for an operator to alert on.

## Audit and redaction

Every state-changing operation is audited through `audit.record`, with a schema
registered in `server/app/core/redaction.py` so the field set cannot drift:

| Action | Fields |
|---|---|
| `evidence_artifact.stored` | `artifact_id`, `package_id`, `bundle_id`, `tenant_id`, `content_sha256`, `backend`, `retain_until`, `through_seq` |
| `evidence_artifact.store_failed` | `artifact_id`, `tenant_id`, `backend`, `reason` (coded, not prose) |
| `evidence_artifact.downloaded` | `artifact_id`, `tenant_id`, `content_sha256`, `digest_verified` |
| `evidence_artifact.deleted` | `artifact_id`, `tenant_id`, `content_sha256`, `reason`, `reason_redacted` |
| `evidence_legal_hold.created` | `hold_id`, `scope`, `scope_id`, `tenant_id`, `name`, `reason`, `reason_redacted`, `expires_at` |
| `evidence_legal_hold.released` | `hold_id`, `scope`, `scope_id`, `tenant_id`, `reason`, `reason_redacted` |
| `evidence_retention.swept` | `expired`, `held`, `deleted`, `failed` (counts only) |

Operator-supplied reasons go through the existing `digest_fields` treatment used
by the alert-lifecycle events, so the reason is recoverable as a digest without
storing free prose in the chain. Destination URIs are recorded; credentials,
presigned URLs, and artifact content never are. The existing
`evidence_bundle.exported` event is extended with `retained` and `artifact_id`
rather than being replaced, so historical events keep their shape.

The sweeper's own event is emitted **only when it changed something**. Anchor
publication deliberately emits no chain event to avoid perpetual churn
(`anchor_publish.publish_pending` explains why); a retention sweep that did
nothing follows the same reasoning and stays out of the chain.

## Schema and migration

One forward-only Alembic revision, `0038`, additive, no backfill:

- `evidence_artifacts` — `id`, `tenant_id` (FK `clients.id`), `package_id`,
  `bundle_id`, `content_sha256`, `content_bytes`, `from_seq`, `through_seq`,
  `signing_key_id`, `backend`, `uri`, `receipt` (JSON), `receipt_sha256`,
  `state`, `retain_until`, `created_by`, `created_at`, `deleted_at`,
  `last_error`. Unique on `(tenant_id, package_id)`; indexed on
  `(state, retain_until)` for the sweeper and on `tenant_id` for listing.
- `evidence_legal_holds` — `id`, `scope`, `scope_id`, `tenant_id`, `name`,
  `reason`, `created_by`, `created_at`, `expires_at`, `released_at`,
  `released_by`, `release_reason`. Indexed on `(scope, scope_id)` and on
  `released_at` for the active-hold lookup.

No existing table changes and no data migration, so `0038` is a no-op on a
deployment that never retains an artifact. Rollback follows the forward-only
policy in `docs/ROLLBACK.md`: crossing back below `0038` requires the
exact-revision restore procedure, not an Alembic downgrade.

## Compatibility and rollout

- **Agent**: no change. Nothing here touches the endpoint, the command
  envelope, or any command kind. A mixed fleet is unaffected.
- **Dashboard**: no change in phase 1. The artifact register and hold controls
  are a follow-up, consistent with #79/#80 shipping API-first.
- **Default off**: with `evidence_store_backend=none` (the default), `retain=true`
  returns `409 evidence_store_disabled` and the sweeper does not run. A
  deployment that does nothing sees no behavior change at all.
- **Rollback**: set `evidence_store_backend=none`. Already-stored artifacts stay
  at the destination under their own Object Lock — which is the point of WORM,
  and worth stating plainly: **enabling this creates objects the operator cannot
  delete until their retention expires**, including in `COMPLIANCE` mode where
  not even the bucket owner can shorten it. The deployment runbook must say so
  before an operator turns it on.

## Settings

Mirroring the `anchor_*` block in `server/app/core/config.py`:

| Setting | Default | Purpose |
|---|---|---|
| `evidence_store_backend` | `none` | `none` / `filesystem` / `s3` |
| `evidence_store_dir` | `/var/lib/nodelink/evidence` | filesystem backend root |
| `evidence_s3_bucket` / `_prefix` / `_region` / `_endpoint_url` | — | S3 destination |
| `evidence_s3_object_lock_mode` | `COMPLIANCE` | `GOVERNANCE` / `COMPLIANCE` |
| `evidence_retention_days` | `2555` (7 years) | deployment default minimum retention |
| `evidence_retain_daily_limit` | `24` | per-tenant retained exports per day |
| `evidence_auto_delete_expired` | `false` | opt-in deletion of expired artifacts |
| `evidence_global_hold_max_days` | `365` | upper bound on a global hold's expiry |
| `evidence_retention_sweep_interval_seconds` | `3600` | sweeper cadence |

Production startup validation rejects `evidence_store_backend=s3` without a
bucket, and a `retention_days` shorter than the anchor retain window, which
would leave an artifact outliving the anchor that proves it.

## Implementation phases

Each phase is independently reviewable and leaves the tree green.

1. **Extract the store.** Move `FilesystemBackend`/`S3Backend` to
   `app/core/immutable_store.py`, generalize the key function, keep anchor
   publication behaviorally identical. Pure refactor; existing anchor tests must
   pass unchanged.
2. **Schema + model.** Revision `0038`, the two tables, no callers yet.
3. **Store on export.** `retain=true`, the admin role floor, the daily cap, the
   synchronous store, `evidence_artifact.stored` / `.store_failed`.
4. **Read back.** Artifact list/detail/content routes with digest verification.
5. **Legal hold.** Create/list/release, coverage resolution, refusal paths.
6. **Sweeper.** Expiry transitions, opt-in deletion, `storage_status` class,
   startup validation.
7. **Docs.** Flip this document's status, update `docs/ARCHITECTURE.md`,
   `docs/RETENTION.md`, `docs/DEPLOYMENT-READINESS.md`, the threat model, and
   the README — only after phase 8 passes.
8. **Live verification.** The manual run below against a real Object Lock
   bucket.

## Test and verification plan

Automated, against the filesystem backend and a fake S3 client, mirroring how
`FakeMeshCentralClient` stands in for MeshCentral:

- **Object lock**: an S3 put carries `ObjectLockMode` and a retain-until equal
  to the frozen `retain_until`; a filesystem write lands `0444`.
- **Retention expiry**: an artifact past `retain_until` transitions to `expired`
  and, with auto-delete off, is *not* removed.
- **Hold conflict**: a hold created after expiry still blocks deletion; a hold
  created concurrently with a sweep blocks it (same-transaction re-check).
- **Hold release**: release is terminal and idempotent; a re-hold is a new row.
- **Global hold bounds**: a `global` hold without an expiry is refused; one past
  `evidence_global_hold_max_days` is refused; an expired global hold stops
  covering artifacts and is not revived by a later sweep.
- **Deletion denial**: delete before expiry → `409`; delete while held → `409`;
  delete of an audit table → impossible by construction (the sweeper's query
  set is asserted).
- **Outage**: destination raises → `503`, row `failed`, no `stored` audit event,
  and the caller still receives their bytes only on the success path.
- **Tamper**: mutating a stored receipt makes verification report `mismatch`;
  mutating the stored object makes `/content` return `409 evidence_artifact_corrupt`.
- **Idempotent re-store**: the same export retained twice writes identical bytes
  to the same key and reconciles onto one row.
- **Tenant isolation**: an operator with no membership gets 404 on every route;
  a `client_readonly` member cannot retain, delete, or hold.
- **Migration**: `0038` applies and is a no-op on a database with no artifacts.

Manual, before the status flips to implemented — automated tests cannot prove a
real destination enforces immutability:

1. Point `evidence_store_backend=s3` at a bucket with Object Lock enabled.
2. Retain an export; confirm the object exists with the expected lock mode and
   retain-until via the destination's own tooling.
3. Attempt to delete that object directly with bucket-owner credentials and
   confirm the destination refuses.
4. Place a hold, confirm the sweeper leaves the artifact alone past expiry,
   release it, and confirm the transition.
5. Verify the audit chain records the full sequence with no credential or
   content in any detail.
6. Capture the responses and audit entries as verification evidence under
   `release-notes/evidence/`.

### Mapping to issue #81 acceptance criteria

| Criterion | Where |
|---|---|
| Contract and all valid/invalid/unavailable/unsupported states documented | API contract and failure-state tables above |
| Authorized at the API boundary, complete secret-redacted evidence | tenant-scoped role floors; redaction schemas; no credentials in receipts |
| Resource limits, retry/idempotency, compatibility, migration, rollback | daily cap, content-addressed idempotent writes, additive `0038`, default-off rollback |
| Objective automated tests and reproducible verification evidence | test plan above, automated plus the manual Object Lock run |

## Settled decisions

These three were open when this design was first written and were decided by the
repository owner before implementation began. They are recorded here because
each one is a policy choice a reviewer would otherwise reasonably question.

**Expiry never deletes by default.** The sweeper transitions `stored → expired`
and reports it; removal happens only when an operator explicitly calls `DELETE`
on an expired artifact, or opts in with `evidence_auto_delete_expired=true`. The
strict reading of "retention enforcement" would have expiry delete, but a
misconfigured short retention would then silently destroy compliance evidence,
and under `COMPLIANCE`-mode Object Lock the destination would refuse the delete
anyway and leave the row and the object disagreeing. Accumulate and report is the
safer failure mode; the cost is that an operator must act to reclaim storage, and
`storage_status` surfaces the expired-but-undeleted backlog so that cost is
visible rather than silent.

**Global holds are time-bounded; other scopes are not.** See *Bounded global
holds* above. Artifact and tenant holds stay open-ended because that is how a
legal hold genuinely behaves; the global scope gets an expiry because its blast
radius is every tenant, including ones that do not exist yet.

**Only the signed ZIP may be retained.** JSON and CSV are byte-reproducible from
a pinned `through_seq`, and the PDF is unsigned — the signed package is the one
artifact whose authenticity is self-contained, so it is the only one that earns
irreversible storage. If an auditor later demands the CSV exactly as delivered,
widening this is an additive follow-up (a new permitted format on the same
`retain=true` path), not a change to anything specified here.

## As-built notes

None yet — this document is design only. This section records what actually
shipped, where it diverged from the design above and why, and is filled in as
the phases land.
