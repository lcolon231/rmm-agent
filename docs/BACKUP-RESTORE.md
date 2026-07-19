# Encrypted backup and restore

NodeLink ships an automated, encrypted PostgreSQL backup and a rehearsable
restore path. The design goals, in order: a backup that exists off the host it
protects, that cannot be read without the passphrase, whose integrity is
checkable before and after decryption, and whose restore is validated at the
application level (audit chain and anchors included) before anything is
promoted.

The scripts live in `deploy/backup/`; application-level validation lives in
`server/scripts/verify_restore.py`. The full flow is exercised end to end in
CI against a disposable PostgreSQL (`server/tests/test_backup_restore.py`).

## Taking a backup

```bash
export NODELINK_DB_URL='postgresql://rmm:...@127.0.0.1:5432/rmm'
export NODELINK_BACKUP_PASSPHRASE_FILE=/etc/nodelink/backup.pass   # 0600, see custody below
export NODELINK_BACKUP_DIR=/var/backups/nodelink
export NODELINK_BACKUP_UPLOAD_CMD='rclone copyto --check-first'    # appended: <enc> <manifest>

deploy/backup/nodelink-backup.sh
```

Each run writes two files, both `0600`:

- `nodelink-backup-<UTC>.dump.enc` — a `pg_dump --format=custom` archive
  streamed straight through `openssl enc -aes-256-cbc -salt -pbkdf2 -iter
  600000`; the plaintext dump never touches disk.
- `nodelink-backup-<UTC>.manifest.json` — schema revision, PostgreSQL and
  pg_dump versions, byte size, and SHA-256 of both the plaintext stream and
  the encrypted artifact.

Failure behavior is fail-closed: any error (including a failing upload hook)
removes the partial artifacts and exits non-zero, so a monitoring check on the
exit code cannot mistake a partial backup for a good one. A backup with no
upload hook configured warns loudly — an on-host backup does not survive the
host.

Schedule it with cron or a systemd timer, and alert on non-zero exit:

```
# /etc/cron.d/nodelink-backup — daily at 02:15 UTC
15 2 * * * nodelink . /etc/nodelink/backup.env && /opt/nodelink/deploy/backup/nodelink-backup.sh || logger -p err -t nodelink-backup "backup FAILED"
```

## Passphrase custody

The passphrase file is the backup: lose it and every backup is unreadable;
leak it and every backup is plaintext to the holder. Keep it 0600, owned by
the backup user, stored ALSO in the operator's secret store (password
manager/vault) off the host, and never in the repository or the backup
destination. Rotating the passphrase only affects future backups; keep the
old passphrase until every backup made under it has aged out of retention.

## Restoring (always a rehearsal first)

Restore never targets the live database. The script refuses any database that
contains tables — you restore into a fresh, isolated database, validate it,
and only then decide to promote.

```bash
createdb nodelink_restore                       # empty scratch database
export NODELINK_RESTORE_DB_URL='postgresql://rmm:...@127.0.0.1:5432/nodelink_restore'
export NODELINK_BACKUP_PASSPHRASE_FILE=/etc/nodelink/backup.pass

deploy/backup/nodelink-restore.sh nodelink-backup-<UTC>.dump.enc nodelink-backup-<UTC>.manifest.json
```

The script verifies, in order: encrypted-artifact checksum against the
manifest, target emptiness, decrypted-dump checksum (a wrong passphrase or
corrupted backup fails here), `pg_restore`, and that the restored
`alembic_version` matches the manifest. Then run application-level
validation:

```bash
cd server
python scripts/verify_restore.py \
  --database-url 'postgresql+asyncpg://rmm:...@127.0.0.1:5432/nodelink_restore' \
  --min-operators 1 --min-agents 1 --min-audit-events 1
```

`verify_restore.py` counts operators, agents, commands, tokens, heartbeats,
and audit rows; verifies the audit hash chain in sequence order; and
recomputes every stored Merkle anchor. Exit 0 means fit to promote.

## Promotion and rollback decisions

Promotion is an explicit operator action, not a script: point the server's
`DATABASE_URL` at the validated restore (or re-restore into the production
database name after stopping the server), confirm the startup schema-revision
guard passes, and record the recovery time and the data-loss window (backup
timestamp to incident) in the incident notes.

Restoring a backup taken at schema revision N onto a server build that
requires revision M > N means running `alembic upgrade head` after restore —
the revision guard will refuse to start otherwise. Never downgrade a schema
in place; NodeLink migrations are forward-only, and going backward means
restoring an older backup with the matching older build after an explicit
data-loss decision.

## What this does not cover yet

- Retention/pruning of old backups and monitoring of backup age are operator
  configuration (cron + the destination's lifecycle rules), not shipped
  automation.
- The external audit anchors published outside the database (issue #76) are
  the recovery cross-check for the audit chain; until they exist, a restored
  chain can only be validated for internal consistency.
