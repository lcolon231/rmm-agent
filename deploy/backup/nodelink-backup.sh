#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Encrypted NodeLink PostgreSQL backup.
#
# Produces two files in $NODELINK_BACKUP_DIR:
#   nodelink-backup-<UTC-STAMP>.dump.enc      AES-256-CBC (PBKDF2) encrypted
#                                             pg_dump custom-format archive
#   nodelink-backup-<UTC-STAMP>.manifest.json checksums, sizes, schema
#                                             revision, and tool versions
#
# The plaintext dump is streamed straight into openssl — it never touches
# disk. The manifest records the SHA-256 of both the plaintext stream and the
# encrypted artifact, so integrity can be checked before AND after decryption.
#
# Required environment:
#   NODELINK_DB_URL                postgresql://user[:pass]@host:port/dbname
#   NODELINK_BACKUP_PASSPHRASE_FILE  file containing the encryption passphrase
#                                    (owner-only permissions; custody is the
#                                    operator's responsibility — losing it
#                                    makes every backup unreadable)
# Optional:
#   NODELINK_BACKUP_DIR            output directory (default /var/backups/nodelink)
#   NODELINK_BACKUP_UPLOAD_CMD     command run on success with the two file
#                                  paths appended; use it to copy the backup
#                                  OFF THIS HOST (an on-host backup does not
#                                  survive the host)
#
# Exit codes: 0 success, non-zero on any failure (fail closed — a partial
# backup is deleted, never left behind looking complete).
set -euo pipefail

: "${NODELINK_DB_URL:?NODELINK_DB_URL is required (postgresql://...)}"
: "${NODELINK_BACKUP_PASSPHRASE_FILE:?NODELINK_BACKUP_PASSPHRASE_FILE is required}"
BACKUP_DIR="${NODELINK_BACKUP_DIR:-/var/backups/nodelink}"

if [ ! -r "$NODELINK_BACKUP_PASSPHRASE_FILE" ]; then
    echo "backup: passphrase file is not readable: $NODELINK_BACKUP_PASSPHRASE_FILE" >&2
    exit 1
fi
if [ ! -s "$NODELINK_BACKUP_PASSPHRASE_FILE" ]; then
    echo "backup: passphrase file is empty: $NODELINK_BACKUP_PASSPHRASE_FILE" >&2
    exit 1
fi

mkdir -p "$BACKUP_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BASE="$BACKUP_DIR/nodelink-backup-$STAMP"
ENC="$BASE.dump.enc"
MANIFEST="$BASE.manifest.json"
PLAIN_SUM_FILE="$(mktemp)"

cleanup_partial() {
    rm -f "$ENC" "$MANIFEST"
    rm -f "$PLAIN_SUM_FILE"
}
trap cleanup_partial ERR
trap 'rm -f "$PLAIN_SUM_FILE"' EXIT

# Schema revision and server version, captured before dumping so the manifest
# describes what was actually backed up.
SCHEMA_REV="$(psql "$NODELINK_DB_URL" -tAc 'SELECT version_num FROM alembic_version' | tr -d '[:space:]')"
if [ -z "$SCHEMA_REV" ]; then
    echo "backup: could not read alembic_version — refusing to back up an unversioned schema" >&2
    exit 1
fi
SERVER_VERSION="$(psql "$NODELINK_DB_URL" -tAc 'SHOW server_version' | tr -d '[:space:]')"

# Stream: pg_dump -> tee(sha256 of plaintext) -> openssl encrypt -> file.
# pipefail makes a pg_dump failure fail the whole pipeline.
pg_dump --format=custom --no-owner "$NODELINK_DB_URL" \
    | tee >(sha256sum | cut -d' ' -f1 > "$PLAIN_SUM_FILE") \
    | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 600000 \
        -pass "file:$NODELINK_BACKUP_PASSPHRASE_FILE" -out "$ENC"

PLAIN_SHA256="$(cat "$PLAIN_SUM_FILE")"
ENC_SHA256="$(sha256sum "$ENC" | cut -d' ' -f1)"
ENC_BYTES="$(stat -c %s "$ENC")"
if [ "$ENC_BYTES" -eq 0 ]; then
    echo "backup: encrypted artifact is empty" >&2
    exit 1
fi
chmod 0600 "$ENC"

cat > "$MANIFEST" <<EOF
{
  "format": "nodelink-backup-manifest",
  "version": 1,
  "created_at_utc": "$STAMP",
  "database": "$(basename "${NODELINK_DB_URL%%\?*}")",
  "schema_revision": "$SCHEMA_REV",
  "postgres_server_version": "$SERVER_VERSION",
  "pg_dump_version": "$(pg_dump --version | awk '{print $NF}')",
  "encryption": "aes-256-cbc, pbkdf2, 600000 iterations, salted",
  "encrypted_file": "$(basename "$ENC")",
  "encrypted_sha256": "$ENC_SHA256",
  "encrypted_bytes": $ENC_BYTES,
  "plaintext_sha256": "$PLAIN_SHA256"
}
EOF
chmod 0600 "$MANIFEST"

echo "backup: wrote $ENC ($ENC_BYTES bytes, schema $SCHEMA_REV)"
echo "backup: manifest $MANIFEST"

if [ -n "${NODELINK_BACKUP_UPLOAD_CMD:-}" ]; then
    # Off-host retention hook. Its failure is a backup failure: a backup that
    # only exists on the host it protects has not met its purpose.
    $NODELINK_BACKUP_UPLOAD_CMD "$ENC" "$MANIFEST"
    echo "backup: upload hook succeeded"
else
    echo "backup: WARNING no NODELINK_BACKUP_UPLOAD_CMD configured — copy $ENC and $MANIFEST off this host" >&2
fi
