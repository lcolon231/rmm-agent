# SPDX-License-Identifier: AGPL-3.0-only
"""External audit-anchor publication tests (issue #76).

Covers, against both the filesystem backend and a mocked S3 Object Lock bucket:
  - scheduled anchor creation + publication, with a tamper-evident receipt
  - idempotent re-publish (deterministic key; no fork, no duplicate row)
  - destination outage -> row stays pending with an error, retry succeeds
  - receipt tamper detection
  - publication-lag reporting / alert threshold
  - the API surface (publication-status, per-anchor receipt) and its authz
  - clean-room verification of a published artifact with no DB write access
  - receipts never carry credentials (redaction)

Run just this file:  pytest tests/test_anchor_publish.py -q
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_anchor_pub.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import boto3  # noqa: E402
import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from moto import mock_aws  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core import anchor_publish, audit  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.models.models import AnchorPublication, AuditAnchor, Operator, OperatorRole  # noqa: E402

SERVER_ROOT = Path(__file__).resolve().parents[1]


@pytest_asyncio.fixture
async def db(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "anchor_publish_backend", "filesystem")
    monkeypatch.setattr(settings, "anchor_publish_dir", str(tmp_path / "anchors"))
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as session:
        yield session
    await engine.dispose()


async def _seed_events(session, n=4):
    for i in range(n):
        await audit.record(session, action=f"anchor.pub.seed{i}")
    await session.commit()


# --------------------------------------------------------------------------- #
# Filesystem backend
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_scheduler_creates_and_publishes(db):
    await _seed_events(db)
    backend = anchor_publish.build_publisher(settings)

    created = await anchor_publish.ensure_current_anchor(db)
    assert created is not None
    result = await anchor_publish.publish_pending(db, backend)
    await db.commit()
    assert result == {"published": 1, "failed": 0}

    pub = (await db.execute(select(AnchorPublication))).scalar_one()
    assert pub.status == "published"
    assert pub.receipt["backend"] == "filesystem"
    assert pub.receipt_sha256 == anchor_publish.receipt_digest(pub.receipt)

    # The external artifact exists and reproduces the root.
    path = Path(pub.receipt["path"])
    assert path.exists()
    doc = json.loads(path.read_text())
    anchor = (await db.execute(select(AuditAnchor))).scalar_one()
    assert doc["merkle_root"] == anchor.merkle_root
    assert doc["event_count"] == anchor.event_count


@pytest.mark.asyncio
async def test_republish_is_idempotent(db):
    await _seed_events(db)
    backend = anchor_publish.build_publisher(settings)
    await anchor_publish.ensure_current_anchor(db)
    await anchor_publish.publish_pending(db, backend)
    await db.commit()

    # Re-running finds nothing to publish and never creates a second row.
    again = await anchor_publish.publish_pending(db, backend)
    await db.commit()
    assert again == {"published": 0, "failed": 0}
    assert len((await db.execute(select(AnchorPublication))).scalars().all()) == 1

    # A fresh anchor over the same chain would re-use the same content-addressed
    # key without error (deterministic path).
    ensure = await anchor_publish.ensure_current_anchor(db)
    assert ensure is None  # chain did not grow -> no new anchor


@pytest.mark.asyncio
async def test_outage_then_retry(db, monkeypatch):
    await _seed_events(db)
    await anchor_publish.ensure_current_anchor(db)
    await db.commit()

    class BrokenBackend:
        name = "filesystem"
        def object_key(self, anchor):
            return "k.json"
        def publish(self, key, payload):
            raise anchor_publish.PublishError("destination unreachable")

    result = await anchor_publish.publish_pending(db, BrokenBackend())
    await db.commit()
    assert result == {"published": 0, "failed": 1}
    pub = (await db.execute(select(AnchorPublication))).scalar_one()
    assert pub.status == "pending"
    assert "unreachable" in pub.last_error
    assert pub.attempts == 1

    # The real backend on retry publishes the same anchor and clears the error.
    backend = anchor_publish.build_publisher(settings)
    result = await anchor_publish.publish_pending(db, backend)
    await db.commit()
    assert result == {"published": 1, "failed": 0}
    await db.refresh(pub)
    assert pub.status == "published"
    assert pub.last_error is None
    assert pub.attempts == 2


@pytest.mark.asyncio
async def test_receipt_tamper_detected(db):
    await _seed_events(db)
    backend = anchor_publish.build_publisher(settings)
    await anchor_publish.ensure_current_anchor(db)
    await anchor_publish.publish_pending(db, backend)
    await db.commit()

    pub = (await db.execute(select(AnchorPublication))).scalar_one()
    assert anchor_publish.verify_receipt(pub) == (True, None)

    # Someone edits the stored receipt but not its digest.
    pub.receipt = {**pub.receipt, "sha256": "0" * 64}
    ok, reason = anchor_publish.verify_receipt(pub)
    assert not ok and reason == "receipt digest mismatch"


@pytest.mark.asyncio
async def test_lag_alert(db, monkeypatch):
    monkeypatch.setattr(settings, "anchor_publish_lag_alert_seconds", 60)
    await _seed_events(db)
    anchor = await anchor_publish.ensure_current_anchor(db)
    # Backdate the anchor so it looks overdue for publication.
    anchor.created_at = datetime.now(timezone.utc) - timedelta(seconds=120)
    await db.commit()

    status = await anchor_publish.publication_status(db)
    assert status.pending == 1
    assert status.published == 0
    assert status.lag_alert is True
    assert status.oldest_unpublished_age_seconds > 60


@pytest.mark.asyncio
async def test_disabled_backend_reports_all_unpublished(db, monkeypatch):
    monkeypatch.setattr(settings, "anchor_publish_backend", "none")
    await _seed_events(db)
    await anchor_publish.ensure_current_anchor(db)
    await db.commit()
    status = await anchor_publish.publication_status(db)
    assert status.backend is None
    assert status.pending == status.total_anchors == 1
    assert status.lag_alert is True


# --------------------------------------------------------------------------- #
# S3 Object Lock backend (mocked)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_s3_backend_publishes_with_object_lock(db, monkeypatch):
    with mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(
            Bucket="nodelink-anchors", ObjectLockEnabledForBucket=True
        )
        monkeypatch.setattr(settings, "anchor_publish_backend", "s3")
        monkeypatch.setattr(settings, "anchor_s3_bucket", "nodelink-anchors")
        monkeypatch.setattr(settings, "anchor_s3_region", "us-east-1")
        monkeypatch.setattr(settings, "anchor_s3_retain_days", 30)

        await _seed_events(db)
        backend = anchor_publish.build_publisher(settings)
        await anchor_publish.ensure_current_anchor(db)
        result = await anchor_publish.publish_pending(db, backend)
        await db.commit()
        assert result == {"published": 1, "failed": 0}

        pub = (await db.execute(select(AnchorPublication))).scalar_one()
        assert pub.status == "published"
        assert pub.receipt["backend"] == "s3"
        assert pub.receipt["bucket"] == "nodelink-anchors"
        assert pub.receipt["version_id"]  # versioning on for object-lock buckets
        assert pub.receipt["object_lock_mode"] == "COMPLIANCE"
        assert pub.uri.startswith("s3://nodelink-anchors/")

        # Receipts must never carry credentials.
        blob = json.dumps(pub.receipt).lower()
        for secret_marker in ("secret", "access_key", "aws_access", "password", "token"):
            assert secret_marker not in blob


# --------------------------------------------------------------------------- #
# API surface
# --------------------------------------------------------------------------- #
@pytest_asyncio.fixture
async def client(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "anchor_publish_backend", "filesystem")
    monkeypatch.setattr(settings, "anchor_publish_dir", str(tmp_path / "anchors"))
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as session:
        session.add(
            Operator(email="anchor@nodelink.test", password_hash=hash_password("pw"),
                     role=OperatorRole.operator)
        )
        await session.commit()

    from app.main import app
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t/api/v1") as c:
        login = await c.post("/auth/login", json={"email": "anchor@nodelink.test", "password": "pw"})
        c.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})
        yield c
    await engine.dispose()


@pytest.mark.asyncio
async def test_api_publication_status_and_receipt(client):
    # Seed + create + publish via the modules, then read through the API.
    async with AsyncSessionLocal() as session:
        await _seed_events(session)
        backend = anchor_publish.build_publisher(settings)
        anchor = await anchor_publish.ensure_current_anchor(session)
        await anchor_publish.publish_pending(session, backend)
        await session.commit()
        anchor_id = anchor.id

    st = (await client.get("/audit/publication-status")).json()
    assert st["backend"] == "filesystem"
    assert st["published"] == 1 and st["pending"] == 0
    assert st["lag_alert"] is False

    rec = (await client.get(f"/audit/anchors/{anchor_id}/receipt")).json()
    assert rec["anchor_id"] == anchor_id
    assert len(rec["publications"]) == 1
    pub = rec["publications"][0]
    assert pub["status"] == "published"
    assert pub["receipt_intact"] is True


@pytest.mark.asyncio
async def test_receipt_endpoint_unknown_anchor_404(client):
    r = await client.get("/audit/anchors/nope/receipt")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_status_requires_auth(client):
    bare = client
    r = await bare.get("/audit/publication-status", headers={"Authorization": "Bearer bad"})
    assert r.status_code == 401


# --------------------------------------------------------------------------- #
# Clean-room verifier (no DB write access)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_clean_room_verifier(db, tmp_path):
    await _seed_events(db)
    backend = anchor_publish.build_publisher(settings)
    anchor = await anchor_publish.ensure_current_anchor(db)
    await anchor_publish.publish_pending(db, backend)
    await db.commit()

    # The artifact as downloaded from the destination.
    pub = (await db.execute(select(AnchorPublication))).scalar_one()
    artifact = Path(pub.receipt["path"])

    # Event hashes exported read-only, in seq order, limited to the covered
    # prefix (an anchor commits to its first event_count events).
    from app.models.models import AuditEvent
    hashes = list(
        (
            await db.execute(
                select(AuditEvent.event_hash)
                .order_by(AuditEvent.seq)
                .limit(anchor.event_count)
            )
        ).scalars().all()
    )
    hashes_file = tmp_path / "hashes.txt"
    hashes_file.write_text("\n".join(hashes))

    ok = subprocess.run(
        [sys.executable, str(SERVER_ROOT / "scripts" / "verify_anchor_receipt.py"),
         "--artifact", str(artifact), "--event-hashes", str(hashes_file)],
        capture_output=True, text=True,
    )
    assert ok.returncode == 0, ok.stderr
    assert "reproduce published root" in ok.stdout

    # Tamper with one exported hash -> verification fails.
    bad = hashes[:]
    bad[0] = "f" * 64
    hashes_file.write_text("\n".join(bad))
    bad_run = subprocess.run(
        [sys.executable, str(SERVER_ROOT / "scripts" / "verify_anchor_receipt.py"),
         "--artifact", str(artifact), "--event-hashes", str(hashes_file)],
        capture_output=True, text=True,
    )
    assert bad_run.returncode == 1
    assert "!=" in bad_run.stderr
