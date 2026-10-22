# Immutable evidence vault, retention, and legal hold (issue #81)

Status: **implemented server side and verified by automated tests** against the
filesystem backend and an in-process S3 Object Lock emulator (moto). It has
not been verified against a live AWS S3, MinIO, or Backblaze B2 bucket, and
there is no dashboard UI yet: the capability is API-only. This is a
compliance-supporting control. It does not by itself make a deployment
compliant with any regulation, and it does not decide how long any particular
record must be kept.

## What it does

The signed evidence package from issue #80 proves what NodeLink reported at
export time, and it embeds the external anchor receipts from issue #76. The
vault keeps those packages where they cannot be quietly replaced or destroyed:

- **Store.** NodeLink builds a signed package for one tenant and writes its
  exact bytes to the configured backend under a content-addressed key, with a
  retention date. On S3 the object is written with Object Lock, so the
  storage enforces the retention, not just NodeLink.
- **Verify.** NodeLink re-reads the exact stored object version. It checks the
  size, the SHA-256, the signed manifest, and the stored receipt digest, and on
  S3 it checks that the storage lock is at least as strong as the record says.
- **Legal hold.** A hold covers one package or a whole tenant, including
  packages stored while it is active. Holds suspend disposal regardless of
  retention.
- **Disposal.** Disposal is always an explicit administrator action. It is
  refused while any hold covers the package or its retention has not elapsed.
  No timer deletes evidence.

What gets retained: the issue #80 ZIP, which carries the logical evidence
document, the tagged PDF, `receipts/anchor-receipts.json` (the exact anchor
publication receipts), the verification public key, and the signed manifest.
The anchor artifacts themselves keep going to their own WORM destination
(`docs/AUDIT-ANCHORING.md`). The vault holds the tenant-scoped,
signature-bound copy of those receipts.

## Backends and what each one actually guarantees

| `EVIDENCE_VAULT_BACKEND` | Enforcement | Guarantee |
|---|---|---|
| `none` (default) | `disabled` | Store requests fail with `evidence_vault_disabled` / `unsupported`. Existing ledger rows stay readable; byte access fails with 503. |
| `filesystem` | `application_only` | Files are written read-only and never overwritten. NodeLink alone refuses early disposal. Anyone with host access can still delete or replace a file unless the directory is a WORM mount. Tamper and absence are *detected* on verify. |
| `s3` | `storage_object_lock` | The bucket must have Object Lock enabled. Every object is written with `ObjectLockMode` and `RetainUntilDate`, plus a legal hold when one applies. Every read, hold change, and delete addresses the exact recorded **version**. `COMPLIANCE` mode cannot be shortened or bypassed by anyone, including the account root. |

```bash
EVIDENCE_VAULT_BACKEND=s3
EVIDENCE_VAULT_S3_BUCKET=your-nodelink-evidence     # Object Lock enabled at creation
EVIDENCE_VAULT_S3_PREFIX=nodelink/evidence
EVIDENCE_VAULT_S3_REGION=us-east-1
EVIDENCE_VAULT_S3_ENDPOINT_URL=                     # MinIO / B2 / other S3-compatible
EVIDENCE_VAULT_S3_OBJECT_LOCK_MODE=COMPLIANCE       # or GOVERNANCE (bypassable; testing)
EVIDENCE_VAULT_RETENTION_DAYS=2555                  # floor for every package (~7 years)
EVIDENCE_VAULT_MAX_RETENTION_DAYS=36500
EVIDENCE_VAULT_VERIFY_INTERVAL_SECONDS=86400
EVIDENCE_VAULT_VERIFY_BATCH_SIZE=100

# filesystem backend
EVIDENCE_VAULT_BACKEND=filesystem
EVIDENCE_VAULT_DIR=/mnt/worm/nodelink-evidence
```

Credentials come only from the standard AWS chain (environment, instance or
task role, `~/.aws`). They are never read from NodeLink settings, and they
never appear in a receipt, an error, an audit event, or a log line. Storage
error messages are reduced to the S3 error code before they leave the backend,
because boto messages can echo request parameters.

The default retention is a placeholder, not legal advice. Set
`EVIDENCE_VAULT_RETENTION_DAYS` to the longest period your obligations
require. A store request may ask for a longer period but never a shorter one.

Two fail-closed checks apply before a package is recorded as retained. The
bucket's Object Lock configuration must read `Enabled`. After the write,
NodeLink reads the object's lock back and requires the configured mode and a
retention date no earlier than requested. A bucket that silently ignored the
lock headers therefore produces `evidence_vault_misconfigured`. It never
produces a record that claims immutability.

## API contract

Base path `/api/v1`. Authorization follows the tenant boundary
(`docs/TENANT-AUTHORIZATION.md`). Any record, hold, or tenant that belongs to
a tenant you cannot see answers 404, exactly like one that does not exist.

| Method and path | Global role | Tenant role | Purpose |
|---|---|---|---|
| `POST /evidence/vault/records` | `operator` | `client_operator` | Build and retain a signed package. Body: `organization_id`, optional `from_seq`, `through_seq`, `record_limit`, `retention_days`. `201` stored, `200` already retained. |
| `GET /evidence/vault/records` | `readonly` | visible | List ledger rows (filters: `organization_id`, `state`; `limit` ≤ 500, `offset`). |
| `GET /evidence/vault/records/{id}` | `readonly` | visible | One ledger row, receipt, `receipt_intact`, hold and integrity state. |
| `GET /evidence/vault/records/{id}/content` | `readonly` | visible | The retained ZIP. Released only when its SHA-256 still matches the record. |
| `POST /evidence/vault/records/{id}/verify` | `readonly` | visible | Re-verify now; returns the updated row. |
| `POST /evidence/vault/records/{id}/dispose` | `admin` | `client_admin` | Delete the stored object (body: `reason`). The row stays as a `deleted` tombstone. |
| `POST /evidence/legal-holds` | `admin` | `client_admin` | Place a hold. Body: `organization_id`, optional `record_id` (omit for tenant-wide), `reason`. |
| `GET /evidence/legal-holds` | `readonly` | visible | List holds (filters: `organization_id`, `status`). |
| `POST /evidence/legal-holds/{id}/release` | `admin` | `client_admin` | Release a hold (body: `reason`). |
| `GET /evidence/vault/status` | `readonly` | own tenants | Backend, enforcement, counts by state and integrity, elapsed-and-unheld count, active holds, pending storage-hold reconciliation, `alert`. |

### States

A record's `state` is `stored` or `deleted`. Its `integrity_state` is one of:

| `integrity_state` | Meaning |
|---|---|
| `unverified` | Not yet checked. Not produced by the current code path, which marks a fresh write `intact`. |
| `intact` | Bytes, signed manifest, receipt, and (on S3) lock all match the record. |
| `tampered` | The object bytes, signed manifest, package ID, or stored receipt differ from what was recorded. |
| `missing` | The recorded object version no longer exists in storage. |
| `unavailable` | Storage could not be reached. This is an outage, not evidence of tamper, and it is never reported as `intact`. |
| `lock_drift` | The storage lock is weaker than recorded: a different mode, an earlier retention date, a legal hold that should be on but is off, or storage refusing a deletion NodeLink expected to succeed. |

A hold's `status` is `active` or `released`. Holds are never deleted.

### Errors

Every coded error is `{"detail": {"code": ..., "state": ...}}`.

| HTTP | `code` | `state` | When |
|---|---|---|---|
| 503 | `evidence_vault_disabled` | `unsupported` | No backend is configured. |
| 503 | `evidence_vault_misconfigured` | `unavailable` | Unknown backend, a missing bucket setting, a bucket without Object Lock, or a lock not applied as requested. |
| 503 | `evidence_vault_unavailable` | `unavailable` | Storage outage on store, read, or dispose. Nothing is recorded as retained. |
| 409 | `evidence_vault_backend_mismatch` | `unsupported` | The record lives on a different backend than the one configured now. |
| 409 | `evidence_object_conflict` | `tampered` | Different bytes already occupy the package's content-addressed key. NodeLink never overwrites them. |
| 409 | `evidence_integrity_failed` | `tampered` | Download refused because the bytes no longer match the record. |
| 409 | `evidence_object_missing` | `missing` | Download refused because the object is gone. |
| 409 | `evidence_package_disposed` / `evidence_record_disposed` | `invalid` | The package was already disposed of. |
| 409 | `evidence_legal_hold_active` | `denied` | Disposal refused: an active hold covers the package. |
| 409 | `evidence_retention_active` | `denied` | Disposal refused: retention has not elapsed. |
| 409 | `evidence_storage_refused_deletion` | `denied` | Storage still enforces a lock. The record is marked `lock_drift`. |
| 409 | `legal_hold_conflict` | `invalid` | An active hold already covers that exact scope. |
| 409 | `legal_hold_not_active` | `invalid` | The hold was already released. |
| 422 | `evidence_retention_below_minimum` / `_above_maximum` | `invalid` | `retention_days` is outside the configured bounds. |

The issue #79/#80 build errors (`evidence_record_limit_exceeded`, chain or
anchor not intact, signing unavailable, and so on) pass through unchanged on
store.

## Retry, idempotency, and concurrency

- A ledger row is unique per `(backend, package_id)`. A store request that
  resolves to an already-retained package returns `200` with the existing row.
  It does not touch storage and does not reset or shorten retention. Pin
  `through_seq` (from `X-NodeLink-Audit-Through-Seq`, or from the row) to make
  retries resolve to the same package.
- The storage key is content-addressed:
  `<prefix>/<tenant>/evidence-package-<package_id>.zip`. A filesystem retry
  after a crash finds identical bytes and succeeds. Different bytes at the key
  fail closed. On S3 a retry writes a new locked version and the row records
  the version it wrote.
- A partial unique index allows at most one *active* hold per
  `(tenant, scope)`, so two concurrent placements cannot both succeed. A
  released scope can be held again; the old hold keeps its history.

## Outage, replication, and reconciliation

- **Store during an outage** fails closed with 503. No row is written,
  `evidence_vault.store_failed` is audited, and the client can retry.
- **A hold placed during an outage is never lost.** The hold row commits, and
  it alone blocks disposal. The response reports `storage_pending`, the status
  endpoint reports `storage_hold_reconciliation_pending` and `alert`, and the
  background sweeper applies the storage hold once the backend is back.
  Releasing a hold during an outage leaves the storage hold **on**, which is
  the safe direction. The sweeper lifts it later. A storage hold is lifted
  only for packages that no other active hold still covers.
- **The sweeper** (`evidence_vault_sweeper`, every
  `EVIDENCE_VAULT_VERIFY_INTERVAL_SECONDS`) reconciles drifted storage holds
  and then re-verifies the least recently verified packages, in bounded
  batches. It audits only a *transition* into `tampered`, `missing`, or
  `lock_drift`, so a quiet vault does not grow the audit chain (the same rule
  anchor publication follows).
- **Replication.** NodeLink verifies the primary bucket only. Cross-region
  replication is a property of the bucket: S3 replication carries Object Lock
  retention to the replica when it is configured to. Losing a replica is not
  detected here. Verify replicas with your storage provider's tooling.

## Recovery and rollback

- **Lost database.** Restore from backup (`docs/BACKUP-RESTORE.md`). Packages
  stored after the backup still exist in storage. Re-storing the same pinned
  package reconciles onto the existing object: filesystem keys match byte for
  byte, and S3 writes a new locked version. Every retained package remains
  verifiable offline (below) without the database.
- **Rollback of the application** removes the API. Stored objects stay
  retained and locked. Schema `0047` is additive and forward-only. Crossing
  back below it requires the exact-revision restore in `docs/ROLLBACK.md`.
- **Rotated signing key.** Verification of an old package needs the public
  key that signed it. Keep retired public keys in a trusted archive
  (`docs/KEY-ROTATION.md`).

## Independent verification

A retained package is an ordinary issue #80 ZIP:

```powershell
aws s3api get-object --bucket your-nodelink-evidence `
  --key nodelink/evidence/<tenant>/evidence-package-<package_id>.zip `
  --version-id <version_id from the record's storage_receipt> evidence.zip
python server/scripts/verify_evidence_package.py evidence.zip `
  --trusted-public-key trusted-evidence-public.pem
```

Get the trusted key through a separately authenticated channel, never from the
archive itself (`docs/EVIDENCE-PACKAGES.md`).

## Audit and redaction

Every store, failed store, download, operator verification, sweep failure
transition, disposal, denied disposal, hold placement, and hold release is
recorded. The events are listed with their exact fields in
`docs/AUDIT-EVENTS.md`. Free-text disposal and hold reasons are stored only as
`reason_sha256` and `reason_bytes` in the audit chain. The verbatim text lives
on the hold row, visible to members of that tenant. No package content,
payload, credential, or presigned URL enters an event.

## Resource bounds

Package size and record limits are inherited from issue #80: at most 64 MiB
per package, 50,000 records maximum. Hold and disposal reasons are limited to
2,000 characters. List endpoints return at most 500 rows. The sweeper handles
`EVIDENCE_VAULT_VERIFY_BATCH_SIZE` packages per pass. Placing or releasing a
tenant-wide hold reconciles every stored package of that tenant within the
request.

## Verification evidence

```powershell
cd server
.venv\Scripts\python -m pytest tests/test_evidence_vault.py tests/test_migrations.py tests/test_redaction.py -q
```

`server/tests/test_evidence_vault.py` covers the following:

- Store authorization (global and tenant role, cross-tenant 404), idempotent
  retry, read-only files, and embedded anchor receipts.
- Digest-checked download, with clean-room subprocess verification of the
  retrieved bytes.
- Retention floor and ceiling, early-disposal denial, disposal after expiry,
  tombstones, and the refused re-store of a disposed package.
- Tenant- and record-scoped holds, conflicts, independent blocking, release
  ordering, double release, and holds applied at store time.
- Tamper of bytes or receipt and object absence, each detected.
- Content-addressed conflict, and recovery after losing the database row.
- S3 Object Lock: COMPLIANCE mode, a storage-side delete refused, legal hold
  ON and OFF in storage, storage-refused disposal flagged as `lock_drift`,
  real expiry followed by disposal, and a shortened lock detected.
- A bucket without Object Lock refused.
- Store during an outage fails closed, a hold survives the outage, and the
  sweeper reconciles it afterwards.
- The sweeper audits only failure transitions.
