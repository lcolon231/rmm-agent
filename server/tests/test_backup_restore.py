# SPDX-License-Identifier: AGPL-3.0-only
"""End-to-end encrypted backup/restore rehearsal (issue #22).

Requires the disposable CI PostgreSQL (TEST_POSTGRES_URL) plus pg_dump,
pg_restore, psql, and openssl on PATH. The rehearsal is the real flow:

  migrate -> seed -> encrypted backup (deploy/backup/nodelink-backup.sh)
  -> restore into an isolated fresh database (nodelink-restore.sh)
  -> application-level validation (scripts/verify_restore.py)

plus the fail-closed paths: tampered artifact, wrong passphrase, and a
non-empty restore target.

Run just this file:  TEST_POSTGRES_URL=... pytest tests/test_backup_restore.py -q
"""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_backup.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import pytest  # noqa: E402
from alembic import command  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402

from tests.test_migrations import migration_config  # noqa: E402

SERVER_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVER_ROOT.parent
BACKUP_SH = REPO_ROOT / "deploy" / "backup" / "nodelink-backup.sh"
RESTORE_SH = REPO_ROOT / "deploy" / "backup" / "nodelink-restore.sh"

_TOOLS = all(shutil.which(t) for t in ("pg_dump", "pg_restore", "psql", "openssl"))

pytestmark = pytest.mark.skipif(
    not os.getenv("TEST_POSTGRES_URL") or not _TOOLS,
    reason="needs TEST_POSTGRES_URL and postgres client tools",
)


def _plain_url(asyncpg_url: str, dbname: str | None = None) -> str:
    """postgresql+asyncpg://... -> postgresql://... (optionally to another db)."""
    plain = asyncpg_url.replace("postgresql+asyncpg://", "postgresql://", 1)
    if dbname is not None:
        parsed = urlparse(plain)
        plain = plain[: len(plain) - len(parsed.path)] + f"/{dbname}"
    return plain


def _admin_url() -> str:
    return _plain_url(os.environ["TEST_POSTGRES_URL"], "postgres")


def _psql(url: str, sql: str) -> str:
    return subprocess.run(
        ["psql", url, "-tAc", sql], check=True, capture_output=True, text=True
    ).stdout.strip()


async def _seed(asyncpg_url: str) -> None:
    """A representative dataset: operator, agent, command, audit chain, anchor."""
    from app.core import anchor as anchor_mod
    from app.core import audit as audit_mod
    from app.core.security import hash_password, hash_token
    from app.models.models import Agent, Client, Command, CommandStatus, CommandKind, Operator, OperatorRole, Site

    engine = create_async_engine(asyncpg_url)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with maker() as db:
            db.add(Operator(email="backup@nodelink.test",
                            password_hash=hash_password("pw"), role=OperatorRole.admin))
            client = Client(name="Backup Clinic")
            db.add(client)
            await db.flush()
            site = Site(client_id=client.id, name="HQ")
            db.add(site)
            await db.flush()
            agent = Agent(site_id=site.id, token_hash=hash_token("agent-token"),
                          hostname="PC-BK", command_envelope_versions=["command-v3"])
            db.add(agent)
            await db.flush()
            db.add(Command(agent_id=agent.id, kind=CommandKind.shell,
                           payload={"script": "echo hi"}, envelope_version="command-v3",
                           status=CommandStatus.succeeded, stdout="hi"))
            for i in range(5):
                await audit_mod.record(db, action=f"backup.seed{i}")
            await db.flush()
            created = await anchor_mod.create_anchor(db)
            assert created is not None
            await db.commit()
    finally:
        await engine.dispose()


@pytest.fixture
def prepared_db(tmp_path: Path):
    """Migrated + seeded source DB; guarantees both DBs are cleaned up so the
    disposable-database assumption of test_migrations still holds."""
    src_async = os.environ["TEST_POSTGRES_URL"]
    admin = _admin_url()
    _psql(admin, "DROP DATABASE IF EXISTS nodelink_restore_test")

    command.upgrade(migration_config(src_async), "head")
    asyncio.run(_seed(src_async))

    passfile = tmp_path / "backup.pass"
    passfile.write_text("correct horse battery staple test passphrase")
    passfile.chmod(0o600)

    yield src_async, passfile

    _psql(admin, "DROP DATABASE IF EXISTS nodelink_restore_test")
    # Return the source DB to pristine emptiness for the migration tests.
    _psql(_plain_url(src_async), "DROP SCHEMA public CASCADE; CREATE SCHEMA public")


def _run_backup(tmp_path: Path, src_async: str, passfile: Path, extra_env=None):
    env = os.environ.copy()
    env.update(
        NODELINK_DB_URL=_plain_url(src_async),
        NODELINK_BACKUP_PASSPHRASE_FILE=str(passfile),
        NODELINK_BACKUP_DIR=str(tmp_path / "backups"),
        **(extra_env or {}),
    )
    return subprocess.run(
        ["bash", str(BACKUP_SH)], env=env, capture_output=True, text=True
    )


def _artifacts(tmp_path: Path) -> tuple[Path, Path]:
    backups = sorted((tmp_path / "backups").glob("*.dump.enc"))
    manifests = sorted((tmp_path / "backups").glob("*.manifest.json"))
    assert backups and manifests, "backup artifacts missing"
    return backups[-1], manifests[-1]


def _run_restore(enc: Path, manifest: Path, passfile: Path, dbname="nodelink_restore_test"):
    env = os.environ.copy()
    env.update(
        NODELINK_RESTORE_DB_URL=_plain_url(os.environ["TEST_POSTGRES_URL"], dbname),
        NODELINK_BACKUP_PASSPHRASE_FILE=str(passfile),
    )
    return subprocess.run(
        ["bash", str(RESTORE_SH), str(enc), str(manifest)],
        env=env, capture_output=True, text=True,
    )


def test_backup_restore_verify_roundtrip(prepared_db, tmp_path: Path):
    src_async, passfile = prepared_db

    bk = _run_backup(tmp_path, src_async, passfile)
    assert bk.returncode == 0, bk.stderr
    enc, manifest = _artifacts(tmp_path)
    # Plaintext must not leak into the encrypted artifact.
    assert b"backup@nodelink.test" not in enc.read_bytes()

    _psql(_admin_url(), "CREATE DATABASE nodelink_restore_test")
    rs = _run_restore(enc, manifest, passfile)
    assert rs.returncode == 0, rs.stderr

    vr = subprocess.run(
        [sys.executable, str(SERVER_ROOT / "scripts" / "verify_restore.py"),
         "--database-url", _plain_url(os.environ["TEST_POSTGRES_URL"], "nodelink_restore_test")
            .replace("postgresql://", "postgresql+asyncpg://", 1),
         "--min-operators", "1", "--min-agents", "1",
         "--min-commands", "1", "--min-audit-events", "5"],
        capture_output=True, text=True, cwd=SERVER_ROOT,
    )
    assert vr.returncode == 0, vr.stderr + vr.stdout
    assert "audit chain intact" in vr.stdout
    assert "anchor" in vr.stdout and "intact" in vr.stdout


def test_tampered_artifact_is_refused(prepared_db, tmp_path: Path):
    src_async, passfile = prepared_db
    assert _run_backup(tmp_path, src_async, passfile).returncode == 0
    enc, manifest = _artifacts(tmp_path)

    data = bytearray(enc.read_bytes())
    data[len(data) // 2] ^= 0xFF
    enc.write_bytes(bytes(data))

    _psql(_admin_url(), "CREATE DATABASE nodelink_restore_test")
    rs = _run_restore(enc, manifest, passfile)
    assert rs.returncode != 0
    assert "checksum mismatch" in rs.stderr


def test_wrong_passphrase_is_refused(prepared_db, tmp_path: Path):
    src_async, passfile = prepared_db
    assert _run_backup(tmp_path, src_async, passfile).returncode == 0
    enc, manifest = _artifacts(tmp_path)

    wrong = tmp_path / "wrong.pass"
    wrong.write_text("not the passphrase")

    _psql(_admin_url(), "CREATE DATABASE nodelink_restore_test")
    rs = _run_restore(enc, manifest, wrong)
    assert rs.returncode != 0


def test_restore_refuses_non_empty_target(prepared_db, tmp_path: Path):
    src_async, passfile = prepared_db
    assert _run_backup(tmp_path, src_async, passfile).returncode == 0
    enc, manifest = _artifacts(tmp_path)

    _psql(_admin_url(), "CREATE DATABASE nodelink_restore_test")
    _psql(_plain_url(os.environ["TEST_POSTGRES_URL"], "nodelink_restore_test"),
          "CREATE TABLE already_here (id int)")
    rs = _run_restore(enc, manifest, passfile)
    assert rs.returncode != 0
    assert "not empty" in rs.stderr


def test_failed_upload_hook_fails_the_backup(prepared_db, tmp_path: Path):
    src_async, passfile = prepared_db
    bk = _run_backup(tmp_path, src_async, passfile,
                     extra_env={"NODELINK_BACKUP_UPLOAD_CMD": "false"})
    assert bk.returncode != 0
