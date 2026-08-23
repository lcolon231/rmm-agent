# SPDX-License-Identifier: AGPL-3.0-only
"""Shared write-once store tests (issue #81, phase 1).

The store is the destination half that audit anchors and compliance evidence
artifacts share. These tests pin the properties both callers depend on:
  - content-addressed idempotency, and fail-closed on a differing object
  - nested keys (evidence is tenant/date-partitioned; anchors are flat)
  - prefix handling per backend
  - Object Lock arguments, including an explicit retain-until overriding the
    destination's rolling window
  - receipts that carry no credentials

Anchor-publication behavior over the database stays in tests/test_anchor_publish.py.

Run just this file:  pytest tests/test_immutable_store.py -q
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_immutable_store.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import boto3  # noqa: E402
import pytest  # noqa: E402
from moto import mock_aws  # noqa: E402

from app.core.immutable_store import (  # noqa: E402
    FilesystemBackend,
    PublishError,
    S3Backend,
    StoreConfig,
    build_backend,
)

BUCKET = "nodelink-store-test"


# --------------------------------------------------------------------------- #
# build_backend
# --------------------------------------------------------------------------- #
def test_disabled_backend_builds_nothing(tmp_path):
    assert build_backend(StoreConfig(backend="none")) is None
    assert build_backend(StoreConfig()) is None


def test_unknown_backend_fails_closed():
    with pytest.raises(PublishError):
        build_backend(StoreConfig(backend="magnetic-tape"))


def test_s3_backend_requires_a_bucket():
    with pytest.raises(PublishError):
        build_backend(StoreConfig(backend="s3"))


# --------------------------------------------------------------------------- #
# Filesystem backend
# --------------------------------------------------------------------------- #
def test_filesystem_writes_read_only_and_receipts_the_digest(tmp_path):
    backend = build_backend(
        StoreConfig(backend="filesystem", directory=str(tmp_path))
    )
    result = backend.publish(backend.object_key("artifact.json"), b"payload")

    path = tmp_path / "artifact.json"
    assert path.read_bytes() == b"payload"
    assert result.uri == f"file://{path}"
    assert result.receipt["sha256"] == hashlib.sha256(b"payload").hexdigest()
    assert result.receipt["bytes"] == len(b"payload")
    # Best-effort read-only bit; the real control is the operator's WORM mount.
    assert path.stat().st_mode & 0o777 == 0o444


def test_filesystem_creates_parents_for_a_partitioned_key(tmp_path):
    """Evidence keys are tenant/date-partitioned; anchor keys are flat. Both
    must land without the caller pre-creating directories."""
    backend = FilesystemBackend(str(tmp_path))
    key = "evidence/tenant-a/2026/08/package-abc-def.zip"

    backend.publish(key, b"zip-bytes", content_type="application/zip")

    assert (tmp_path / key).read_bytes() == b"zip-bytes"


def test_filesystem_republish_of_identical_bytes_is_idempotent(tmp_path):
    backend = FilesystemBackend(str(tmp_path))

    first = backend.publish("artifact.json", b"same")
    second = backend.publish("artifact.json", b"same")

    assert first.uri == second.uri
    assert first.receipt == second.receipt
    assert list(tmp_path.iterdir()) == [tmp_path / "artifact.json"]


def test_filesystem_differing_bytes_at_one_key_fail_closed(tmp_path):
    """A content-addressed key holding different bytes is corruption or a WORM
    violation. Overwriting it would destroy evidence, so we refuse."""
    backend = FilesystemBackend(str(tmp_path))
    backend.publish("artifact.json", b"original")

    with pytest.raises(PublishError):
        backend.publish("artifact.json", b"tampered")

    assert (tmp_path / "artifact.json").read_bytes() == b"original"


def test_filesystem_key_carries_no_prefix(tmp_path):
    assert FilesystemBackend(str(tmp_path)).object_key("a.json") == "a.json"


# --------------------------------------------------------------------------- #
# S3 backend
# --------------------------------------------------------------------------- #
def test_s3_object_key_applies_the_prefix():
    backend = S3Backend(
        StoreConfig(backend="s3", bucket=BUCKET, prefix="nodelink/evidence/")
    )
    assert backend.object_key("a.zip") == "nodelink/evidence/a.zip"

    unprefixed = S3Backend(StoreConfig(backend="s3", bucket=BUCKET))
    assert unprefixed.object_key("a.zip") == "a.zip"


def test_s3_publish_sets_object_lock_from_the_retention_window():
    with mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(
            Bucket=BUCKET, ObjectLockEnabledForBucket=True
        )
        backend = S3Backend(
            StoreConfig(
                backend="s3", bucket=BUCKET, region="us-east-1", retain_days=30
            )
        )
        captured: dict = {}

        real_put = backend._get_client().put_object

        def capture(**kwargs):
            captured.update(kwargs)
            return real_put(**kwargs)

        backend._client.put_object = capture
        result = backend.publish("a.json", b"payload")

        assert captured["ObjectLockMode"] == "COMPLIANCE"
        retain = captured["ObjectLockRetainUntilDate"]
        assert timedelta(days=29) < retain - datetime.now(timezone.utc) <= timedelta(days=30)
        assert captured["ContentType"] == "application/json"
        assert result.receipt["object_lock_mode"] == "COMPLIANCE"
        assert result.receipt["retain_until"] == retain.isoformat()


def test_s3_explicit_retain_until_overrides_the_rolling_window():
    """An evidence artifact freezes its own retain_until at creation. Resolving
    it again at write time would let a later config change move it."""
    with mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(
            Bucket=BUCKET, ObjectLockEnabledForBucket=True
        )
        backend = S3Backend(
            StoreConfig(
                backend="s3", bucket=BUCKET, region="us-east-1", retain_days=30
            )
        )
        frozen = datetime.now(timezone.utc) + timedelta(days=2555)
        captured: dict = {}
        real_put = backend._get_client().put_object

        def capture(**kwargs):
            captured.update(kwargs)
            return real_put(**kwargs)

        backend._client.put_object = capture
        backend.publish("a.zip", b"payload", content_type="application/zip",
                        retain_until=frozen)

        assert captured["ObjectLockRetainUntilDate"] == frozen
        assert captured["ContentType"] == "application/zip"


def test_s3_without_a_retention_window_sets_no_lock():
    with mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(
            Bucket=BUCKET, ObjectLockEnabledForBucket=True
        )
        backend = S3Backend(
            StoreConfig(backend="s3", bucket=BUCKET, region="us-east-1")
        )
        captured: dict = {}
        real_put = backend._get_client().put_object

        def capture(**kwargs):
            captured.update(kwargs)
            return real_put(**kwargs)

        backend._client.put_object = capture
        result = backend.publish("a.json", b"payload")

        assert "ObjectLockMode" not in captured
        assert "ObjectLockRetainUntilDate" not in captured
        assert "retain_until" not in result.receipt


def test_s3_destination_failure_raises_publish_error():
    with mock_aws():
        # No bucket created: put_object fails at the destination.
        backend = S3Backend(
            StoreConfig(backend="s3", bucket="missing-bucket", region="us-east-1")
        )
        with pytest.raises(PublishError):
            backend.publish("a.json", b"payload")


def test_receipts_never_carry_credentials(tmp_path):
    """A receipt is persisted and returned by the API. Anything that could
    authenticate must stay inside the client."""
    forbidden = ("access", "secret", "token", "credential", "signature",
                 "password", "presigned", "x-amz-")

    fs = FilesystemBackend(str(tmp_path)).publish("a.json", b"payload").receipt
    with mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(
            Bucket=BUCKET, ObjectLockEnabledForBucket=True
        )
        s3 = S3Backend(
            StoreConfig(backend="s3", bucket=BUCKET, region="us-east-1",
                        retain_days=30)
        ).publish("a.json", b"payload").receipt

    for receipt in (fs, s3):
        blob = repr(receipt).lower()
        for needle in forbidden:
            assert needle not in blob, f"{needle!r} leaked into a receipt"
