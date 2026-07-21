# Audit anchoring and external publication

NodeLink's audit log is a hash chain with monotonic sequence numbers: altering
any event breaks every link after it, and a periodic verifier detects it. That
proves *internal* consistency. It does **not** stop an attacker who owns the
database from rewriting the whole chain consistently — recomputing every hash
so the chain check still passes. The defense against that is **anchoring**:
commit to the chain's state with a Merkle root and publish that root somewhere
the operator (or an attacker with database access) cannot alter. Once an
external copy exists, no rewrite of the covered prefix can reproduce the
published root, so the tampering is detectable by anyone holding the receipt.

This document covers the automated publication of those roots (issue #76). The
Merkle construction itself is in `app/core/anchor.py` and the threat-model
document.

## What runs

A background task (`anchor_publisher` in `app/core/tasks.py`) wakes every
`ANCHOR_PUBLISH_INTERVAL_SECONDS` (default 3600) and:

1. Creates a new anchor if the chain has grown since the last one (idempotent —
   no new anchor when nothing was added, so publication does not itself cause
   churn; publication is not recorded as an audit event).
2. Publishes every unpublished anchor to the configured backend.
3. Records an `AnchorPublication` row per (anchor, backend): status, the
   destination URI, the backend's **receipt**, a `receipt_sha256` over that
   receipt, attempt count, and any last error.
4. Logs a warning when the oldest unpublished anchor is older than
   `ANCHOR_PUBLISH_LAG_ALERT_SECONDS` (default 7200) — the window during which
   a database-owning attacker could rewrite history before any external copy
   exists.

Publication is idempotent: the destination key is content-addressed
(`anchor-<event_count>-<merkle_root>.json`), so a retry after a crash writes
identical bytes rather than forking, and each publication row is unique per
(anchor, backend).

## Configuration

```bash
ANCHOR_PUBLISH_BACKEND=s3            # none (default) | filesystem | s3
ANCHOR_PUBLISH_INTERVAL_SECONDS=3600
ANCHOR_PUBLISH_LAG_ALERT_SECONDS=7200
```

Publication is **opt-in**. With `none` (the default) the server runs but the
publisher logs a loud warning in production and `GET /audit/publication-status`
reports every anchor as unpublished — the gap is visible, never silent.

### S3-compatible Object Lock (recommended)

```bash
ANCHOR_PUBLISH_BACKEND=s3
ANCHOR_S3_BUCKET=your-nodelink-anchors
ANCHOR_S3_PREFIX=nodelink/anchors
ANCHOR_S3_REGION=us-east-1
# For MinIO / Backblaze B2 / other S3-compatible stores:
ANCHOR_S3_ENDPOINT_URL=https://minio.internal:9000
ANCHOR_S3_OBJECT_LOCK_MODE=COMPLIANCE   # GOVERNANCE | COMPLIANCE
ANCHOR_S3_RETAIN_DAYS=3650
```

The bucket **must have Object Lock enabled** (set at bucket creation).
`COMPLIANCE` mode means not even the account root can delete or overwrite an
object before its retention date — this is what makes the anchor immutable
against an attacker who also compromised the NodeLink host. `GOVERNANCE` allows
a specially-permissioned user to bypass, which is weaker but useful in testing.

Credentials come from the standard AWS credential chain (environment,
instance/task role, `~/.aws`). They are **never** read from NodeLink settings
and **never** stored in a receipt. The receipt holds only the bucket, key,
object version-id, ETag, and payload SHA-256.

MinIO is a zero-cost self-hosted option that supports Object Lock and is what
CI exercises (via a mock). Backblaze B2 and AWS S3 are inexpensive hosted
options.

### Filesystem / WORM

```bash
ANCHOR_PUBLISH_BACKEND=filesystem
ANCHOR_PUBLISH_DIR=/mnt/worm/nodelink-anchors
```

Writes each anchor as a read-only file. This is only as immutable as the mount:
point it at a WORM volume, an object-lock-backed filesystem, or a directory
that is continuously synced to append-only storage. On an ordinary disk it is a
convenience, not a security control.

## Operator visibility

- `GET /api/v1/audit/publication-status` (readonly) — backend, total anchors,
  published/pending counts, oldest-unpublished age, `lag_alert`, last error.
- `GET /api/v1/audit/anchors/{id}/receipt` (readonly) — the receipt(s) for an
  anchor with a `receipt_intact` tamper check.
- `GET /api/v1/audit/anchors` and `.../{id}/verify` — the existing local anchor
  list and Merkle re-verification.

## Independent (clean-room) verification

The point of external publication is that someone can verify history **without
trusting the NodeLink database**. To do so with no database write access:

1. Download the anchor artifact from the external destination, e.g.
   `aws s3 cp s3://your-bucket/nodelink/anchors/anchor-000000000042-<root>.json .`
2. Export the covered event hashes read-only, in sequence order:
   ```bash
   psql "$READONLY_URL" -tAc \
     "SELECT event_hash FROM audit_events ORDER BY seq LIMIT 42" > hashes.txt
   ```
3. Recompute and compare, using the standalone verifier (it reimplements the
   Merkle construction so it does not depend on NodeLink):
   ```bash
   python server/scripts/verify_anchor_receipt.py \
     --artifact anchor-000000000042-<root>.json --event-hashes hashes.txt
   ```
   Exit 0 means the published root and the events agree; exit 1 means history
   was altered (or the wrong inputs were supplied).

Because the artifact came from immutable external storage, a match proves the
covered events are exactly those that existed when the anchor was published —
even if the live database was rewritten afterwards.

## Failure and recovery

- **Destination outage:** the publication row stays `pending` with `last_error`
  set; the next scheduler cycle retries. Lag past the threshold alerts.
- **Receipt tamper:** `receipt_sha256` no longer matches the stored receipt;
  the receipt endpoint reports `receipt_intact: false`.
- **Lost database:** restore from backup (`docs/BACKUP-RESTORE.md`); anchors
  already published remain in external storage and can be re-verified against
  the restored events. Re-publishing a restored anchor is idempotent.
- **No backend configured:** anchors accumulate unpublished; configure a
  backend and the next cycle publishes the backlog oldest-first.
