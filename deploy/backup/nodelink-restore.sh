#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Restore an encrypted NodeLink backup into an ISOLATED, EMPTY database.
#
# This script deliberately refuses to restore over a database that contains
# any tables: restoring is rehearsed into a scratch database first, validated
# with server/scripts/verify_restore.py, and only then promoted by the
# operator (repoint the server's DATABASE_URL, or dump/restore again into the
# real target after an explicit decision). It never drops anything.
#
# Usage:
#   nodelink-restore.sh <backup.dump.enc> <backup.manifest.json>
#
# Required environment:
#   NODELINK_RESTORE_DB_URL          postgresql://... of an EMPTY database
#   NODELINK_BACKUP_PASSPHRASE_FILE  passphrase file used at backup time
# Optional:
#   PYTHON                           Python interpreter (default: python3)
#
# Exit codes: 0 success, non-zero on any failure (checksum mismatch, wrong
# passphrase, non-empty target, pg_restore error).
set -euo pipefail

ENC="${1:?usage: nodelink-restore.sh <backup.dump.enc> <backup.manifest.json>}"
MANIFEST="${2:?usage: nodelink-restore.sh <backup.dump.enc> <backup.manifest.json>}"
: "${NODELINK_RESTORE_DB_URL:?NODELINK_RESTORE_DB_URL is required (postgresql://...)}"
: "${NODELINK_BACKUP_PASSPHRASE_FILE:?NODELINK_BACKUP_PASSPHRASE_FILE is required}"
PYTHON="${PYTHON:-python3}"

[ -r "$ENC" ] || { echo "restore: cannot read $ENC" >&2; exit 1; }
[ -r "$MANIFEST" ] || { echo "restore: cannot read $MANIFEST" >&2; exit 1; }

# 1. Integrity of the encrypted artifact against the manifest, before
#    touching the passphrase or the database.
WANT_ENC_SHA="$("$PYTHON" -c "import json,sys; print(json.load(open(sys.argv[1]))['encrypted_sha256'])" "$MANIFEST")"
GOT_ENC_SHA="$(sha256sum < "$ENC" | cut -d' ' -f1)"
if [ "$WANT_ENC_SHA" != "$GOT_ENC_SHA" ]; then
    echo "restore: encrypted artifact checksum mismatch (want $WANT_ENC_SHA got $GOT_ENC_SHA)" >&2
    exit 1
fi

# 2. The target must be empty — isolation is the whole point.
TABLES="$(psql "$NODELINK_RESTORE_DB_URL" -tAc \
    "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'")"
if [ "$TABLES" != "0" ]; then
    echo "restore: target database is not empty ($TABLES tables) — refusing; restore into a fresh database" >&2
    exit 1
fi

# 3. Decrypt to a private temp file, verify the plaintext checksum, restore.
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
DUMP="$WORK/backup.dump"

openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \
    -pass "file:$NODELINK_BACKUP_PASSPHRASE_FILE" -in "$ENC" -out "$DUMP"

WANT_PLAIN_SHA="$("$PYTHON" -c "import json,sys; print(json.load(open(sys.argv[1]))['plaintext_sha256'])" "$MANIFEST")"
GOT_PLAIN_SHA="$(sha256sum < "$DUMP" | cut -d' ' -f1)"
if [ "$WANT_PLAIN_SHA" != "$GOT_PLAIN_SHA" ]; then
    echo "restore: decrypted dump checksum mismatch — wrong passphrase file or corrupted backup" >&2
    exit 1
fi

pg_restore --no-owner --dbname="$NODELINK_RESTORE_DB_URL" "$DUMP"

# 4. Schema revision of the restored database must match the manifest.
WANT_REV="$("$PYTHON" -c "import json,sys; print(json.load(open(sys.argv[1]))['schema_revision'])" "$MANIFEST")"
GOT_REV="$(psql "$NODELINK_RESTORE_DB_URL" -tAc 'SELECT version_num FROM alembic_version' | tr -d '[:space:]')"
if [ "$WANT_REV" != "$GOT_REV" ]; then
    echo "restore: schema revision mismatch (manifest $WANT_REV, restored $GOT_REV)" >&2
    exit 1
fi

echo "restore: restored into $NODELINK_RESTORE_DB_URL at schema revision $GOT_REV"
echo "restore: now run application-level validation:"
echo "  cd server && python scripts/verify_restore.py --database-url '<asyncpg url of restored db>'"
