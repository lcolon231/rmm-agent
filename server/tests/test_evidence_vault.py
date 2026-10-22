# SPDX-License-Identifier: AGPL-3.0-only
"""Immutable evidence storage, retention, and legal hold (issue #81).

Covers object lock, retention expiry, hold conflict/release, deletion denial,
storage outage and reconciliation, tamper, and database-loss recovery, plus the
authorization and audit boundaries of every endpoint.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_evidence_vault.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")
_PW = os.environ.setdefault("NODELINK_TEST_VAULT_PW", "vault-pw")

import boto3  # noqa: E402
import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from moto import mock_aws  # noqa: E402
from sqlalchemy import delete, select, update  # noqa: E402

from app.core import (  # noqa: E402
    anchor,
    anchor_publish,
    audit,
    evidence_bundles,
    evidence_packages,
    evidence_vault,
)
from app.core.config import settings  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.keyring import active_signing_key  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    AnchorPublication,
    AuditEvent,
    Client,
    ClientRole,
    EvidenceLegalHold,
    EvidenceVaultRecord,
    Operator,
    OperatorClientMembership,
    OperatorRole,
)

_SENTINEL = "nlk-vault-sensitive-hold-reason-7f1c"
_BUCKET = "nodelink-evidence-vault"
_SERVER_ROOT = Path(__file__).resolve().parents[1]

# (email, global role, client role on tenant A, client role on tenant B)
_PEOPLE = {
    "admin": ("vault-admin@nodelink.test", OperatorRole.admin, ClientRole.client_admin, None),
    "operator": ("vault-op@nodelink.test", OperatorRole.operator, ClientRole.client_operator, None),
    "reader": ("vault-reader@nodelink.test", OperatorRole.readonly, ClientRole.client_readonly, None),
    "weak_admin": ("vault-weak@nodelink.test", OperatorRole.admin, ClientRole.client_operator, None),
    "other": ("vault-other@nodelink.test", OperatorRole.admin, None, ClientRole.client_admin),
}


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def vault(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "evidence_vault_backend", "filesystem")
    monkeypatch.setattr(settings, "evidence_vault_dir", str(tmp_path / "vault"))
    monkeypatch.setattr(settings, "evidence_vault_retention_days", 30)
    monkeypatch.setattr(settings, "evidence_vault_max_retention_days", 3650)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        tenant_a = Client(name="Alpha Vault")
        tenant_b = Client(name="Bravo Vault")
        people = {
            key: Operator(email=email, password_hash=hash_password(_PW), role=role)
            for key, (email, role, _a, _b) in _PEOPLE.items()
        }
        db.add_all([tenant_a, tenant_b, *people.values()])
        await db.flush()
        for key, (_email, _role, role_a, role_b) in _PEOPLE.items():
            for tenant, role in ((tenant_a, role_a), (tenant_b, role_b)):
                if role is not None:
                    db.add(
                        OperatorClientMembership(
                            operator_id=people[key].id,
                            client_id=tenant.id,
                            role=role,
                            granted_by="seed",
                            reason="vault test",
                        )
                    )
        for tenant in (tenant_a, tenant_b):
            await audit.record(
                db,
                action="agent.offline",
                actor="seed",
                organization_id=tenant.id,
                detail={"last_seen_at": "2026-10-21T00:00:00+00:00"},
            )
        anchored = await anchor.create_anchor(db)
        receipt = {"backend": "filesystem", "path": "anchors/a.json", "sha256": "c" * 64, "bytes": 200}
        db.add(
            AnchorPublication(
                anchor_id=anchored.id,
                backend="filesystem",
                status="published",
                uri="file://anchors/a.json",
                receipt=receipt,
                receipt_sha256=anchor_publish.receipt_digest(receipt),
                attempts=1,
                published_at=datetime.now(timezone.utc),
            )
        )
        await db.commit()
        ids = {"a": tenant_a.id, "b": tenant_b.id, "receipt_sha256": anchor_publish.receipt_digest(receipt)}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test/api/v1") as client:
        tokens = {}
        for key, (email, *_rest) in _PEOPLE.items():
            login = await client.post("/auth/login", json={"email": email, "password": _PW})
            assert login.status_code == 200, login.text
            tokens[key] = login.json()["access_token"]
        yield client, ids, tokens, tmp_path / "vault"
    await engine.dispose()


async def _store(client, tokens, tenant_id, *, who="operator", **extra):
    return await client.post(
        "/evidence/vault/records",
        json={"organization_id": tenant_id, **extra},
        headers=_auth(tokens[who]),
    )


async def _events(action: str) -> list[AuditEvent]:
    async with AsyncSessionLocal() as db:
        return list(
            (
                await db.execute(
                    select(AuditEvent).where(AuditEvent.action == action).order_by(AuditEvent.seq)
                )
            ).scalars().all()
        )


async def _expire_retention(record_id: str) -> None:
    async with AsyncSessionLocal() as db:
        await db.execute(
            update(EvidenceVaultRecord)
            .where(EvidenceVaultRecord.id == record_id)
            .values(retain_until=datetime.now(timezone.utc) - timedelta(seconds=5))
        )
        await db.commit()


# --------------------------------------------------------------------------- #
# Store, idempotency, authorization, clean-room verification
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_store_is_authorized_idempotent_and_clean_room_verifiable(vault):
    client, ids, tokens, vault_dir = vault

    assert (await _store(client, tokens, ids["a"], who="reader")).status_code == 403
    assert (await _store(client, tokens, ids["b"], who="operator")).status_code == 404
    missing = await _store(client, tokens, "no-such-tenant")
    assert missing.status_code == 404

    first = await _store(client, tokens, ids["a"])
    assert first.status_code == 201, first.text
    body = first.json()
    record = body["record"]
    assert body["created"] is True
    assert record["state"] == "stored"
    assert record["integrity_state"] == "intact"
    assert record["retention_mode"] == "application"
    assert record["receipt_intact"] is True
    assert record["legal_hold_active"] is False
    retain_until = datetime.fromisoformat(record["retain_until"])
    assert timedelta(days=29) < retain_until - datetime.now(timezone.utc) <= timedelta(days=30)

    stored = vault_dir / ids["a"] / f"evidence-package-{record['package_id']}.zip"
    assert stored.is_file()
    assert not os.access(stored, os.W_OK)  # written read-only

    # The retained package embeds the external anchor receipts.
    members = evidence_packages.read_archive(stored.read_bytes())
    receipts = json.loads(members["receipts/anchor-receipts.json"])
    assert ids["receipt_sha256"] in json.dumps(receipts)

    # A retry pinned to the same audit prefix is the same package: no second
    # object, no reset of retention, no second "stored" event.
    retry = await _store(client, tokens, ids["a"], through_seq=record["through_seq"])
    assert retry.status_code == 200, retry.text
    assert retry.json()["created"] is False
    assert retry.json()["record"]["id"] == record["id"]
    assert retry.json()["record"]["retain_until"] == record["retain_until"]
    assert len(await _events("evidence_vault.stored")) == 1

    content = await client.get(
        f"/evidence/vault/records/{record['id']}/content", headers=_auth(tokens["reader"])
    )
    assert content.status_code == 200
    assert content.headers["x-nodelink-evidence-package-id"] == record["package_id"]
    verified = evidence_packages.verify_signed_package(
        content.content, trusted_public_key_pem=active_signing_key().public_key_pem.encode()
    )
    assert verified.package_id == record["package_id"]
    retrieved = await _events("evidence_vault.retrieved")
    assert retrieved[-1].detail["sha256"] == record["sha256"]

    # Independent verification of the retrieved bytes, with no NodeLink imports.
    archive = vault_dir.parent / "retrieved.zip"
    trusted = vault_dir.parent / "trusted.pem"
    archive.write_bytes(content.content)
    trusted.write_bytes(active_signing_key().public_key_pem.encode())
    checked = subprocess.run(
        [sys.executable, str(_SERVER_ROOT / "scripts" / "verify_evidence_package.py"),
         str(archive), "--trusted-public-key", str(trusted)],
        capture_output=True, text=True, check=False,
    )
    assert checked.returncode == 0, checked.stderr

    # Cross-tenant: indistinguishable from absent, on every read.
    for path in ("", "/content"):
        response = await client.get(
            f"/evidence/vault/records/{record['id']}{path}", headers=_auth(tokens["other"])
        )
        assert response.status_code == 404
    response = await client.post(
        f"/evidence/vault/records/{record['id']}/verify", headers=_auth(tokens["other"])
    )
    assert response.status_code == 404
    listed = await client.get("/evidence/vault/records", headers=_auth(tokens["other"]))
    assert listed.json()["items"] == []
    listed = await client.get("/evidence/vault/records", headers=_auth(tokens["reader"]))
    assert [item["id"] for item in listed.json()["items"]] == [record["id"]]

    stored_event = (await _events("evidence_vault.stored"))[0]
    assert stored_event.organization_id == ids["a"]
    assert stored_event.detail["package_id"] == record["package_id"]


@pytest.mark.asyncio
async def test_disabled_misconfigured_and_invalid_requests_are_explicit(vault, monkeypatch):
    client, ids, tokens, _vault_dir = vault

    below = await _store(client, tokens, ids["a"], retention_days=1)
    assert below.status_code == 422
    assert below.json()["detail"]["code"] == "evidence_retention_below_minimum"
    above = await _store(client, tokens, ids["a"], retention_days=99999)
    assert above.json()["detail"]["code"] == "evidence_retention_above_maximum"
    longer = await _store(client, tokens, ids["a"], retention_days=400)
    assert longer.status_code == 201
    retain_until = datetime.fromisoformat(longer.json()["record"]["retain_until"])
    assert retain_until - datetime.now(timezone.utc) > timedelta(days=399)

    monkeypatch.setattr(settings, "evidence_vault_backend", "none")
    disabled = await _store(client, tokens, ids["a"])
    assert disabled.status_code == 503
    assert disabled.json()["detail"] == {"code": "evidence_vault_disabled", "state": "unsupported"}
    record_id = longer.json()["record"]["id"]
    # Existing records stay readable; byte access needs the backend.
    assert (await client.get(f"/evidence/vault/records/{record_id}", headers=_auth(tokens["reader"]))).status_code == 200
    content = await client.get(f"/evidence/vault/records/{record_id}/content", headers=_auth(tokens["reader"]))
    assert content.status_code == 503
    status = (await client.get("/evidence/vault/status", headers=_auth(tokens["reader"]))).json()
    assert status["enforcement"] == "disabled"
    assert status["alert"] is True  # evidence depends on a vault that is off

    monkeypatch.setattr(settings, "evidence_vault_backend", "tape")
    broken = await _store(client, tokens, ids["a"])
    assert broken.json()["detail"] == {"code": "evidence_vault_misconfigured", "state": "unavailable"}

    monkeypatch.setattr(settings, "evidence_vault_backend", "s3")
    monkeypatch.setattr(settings, "evidence_vault_s3_bucket", _BUCKET)
    mismatch = await client.post(f"/evidence/vault/records/{record_id}/verify", headers=_auth(tokens["reader"]))
    assert mismatch.status_code == 409
    assert mismatch.json()["detail"]["code"] == "evidence_vault_backend_mismatch"


# --------------------------------------------------------------------------- #
# Retention and disposal
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_retention_blocks_disposal_until_it_elapses(vault):
    client, ids, tokens, vault_dir = vault
    record = (await _store(client, tokens, ids["a"])).json()["record"]
    dispose = f"/evidence/vault/records/{record['id']}/dispose"
    reason = {"reason": "retention schedule"}

    assert (await client.post(dispose, json=reason, headers=_auth(tokens["operator"]))).status_code == 403
    assert (await client.post(dispose, json=reason, headers=_auth(tokens["weak_admin"]))).status_code == 403
    assert (await client.post(dispose, json=reason, headers=_auth(tokens["other"]))).status_code == 404

    early = await client.post(dispose, json=reason, headers=_auth(tokens["admin"]))
    assert early.status_code == 409
    assert early.json()["detail"] == {"code": "evidence_retention_active", "state": "denied"}
    denied = await _events("evidence_vault.deletion_denied")
    assert denied[-1].detail["code"] == "evidence_retention_active"
    stored = vault_dir / ids["a"] / f"evidence-package-{record['package_id']}.zip"
    assert stored.is_file()

    await _expire_retention(record["id"])
    done = await client.post(dispose, json={"reason": _SENTINEL}, headers=_auth(tokens["admin"]))
    assert done.status_code == 200, done.text
    assert done.json()["state"] == "deleted"
    assert not stored.exists()
    deleted = await _events("evidence_vault.deleted")
    assert _SENTINEL not in json.dumps(deleted[-1].detail)
    assert deleted[-1].detail["reason_bytes"] == len(_SENTINEL)

    # The ledger keeps a tombstone; the bytes and a re-store are refused.
    again = await client.post(dispose, json=reason, headers=_auth(tokens["admin"]))
    assert again.status_code == 409
    assert again.json()["detail"]["code"] == "evidence_record_disposed"
    content = await client.get(f"/evidence/vault/records/{record['id']}/content", headers=_auth(tokens["reader"]))
    assert content.json()["detail"]["code"] == "evidence_record_disposed"
    restore = await _store(client, tokens, ids["a"], through_seq=record["through_seq"])
    assert restore.status_code == 409
    assert restore.json()["detail"]["code"] == "evidence_package_disposed"


# --------------------------------------------------------------------------- #
# Legal hold
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_legal_hold_conflict_release_and_deletion_denial(vault):
    client, ids, tokens, _vault_dir = vault
    record = (await _store(client, tokens, ids["a"])).json()["record"]
    await _expire_retention(record["id"])
    holds = "/evidence/legal-holds"
    dispose = f"/evidence/vault/records/{record['id']}/dispose"

    tenant_hold_body = {"organization_id": ids["a"], "reason": _SENTINEL}
    assert (await client.post(holds, json=tenant_hold_body, headers=_auth(tokens["weak_admin"]))).status_code == 403
    assert (await client.post(holds, json=tenant_hold_body, headers=_auth(tokens["other"]))).status_code == 404
    cross = {"organization_id": ids["b"], "record_id": record["id"], "reason": "x"}
    assert (await client.post(holds, json=cross, headers=_auth(tokens["other"]))).status_code == 404

    tenant_hold = await client.post(holds, json=tenant_hold_body, headers=_auth(tokens["admin"]))
    assert tenant_hold.status_code == 201, tenant_hold.text
    assert tenant_hold.json()["covered_records"] == 1
    conflict = await client.post(holds, json=tenant_hold_body, headers=_auth(tokens["admin"]))
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["code"] == "legal_hold_conflict"
    record_hold = await client.post(
        holds, json={**tenant_hold_body, "record_id": record["id"]}, headers=_auth(tokens["admin"])
    )
    assert record_hold.status_code == 201

    placed = await _events("evidence_legal_hold.placed")
    assert _SENTINEL not in json.dumps([event.detail for event in placed])

    # Retention has elapsed, yet every active hold independently blocks disposal.
    for release_id in (tenant_hold.json()["hold"]["id"], None):
        denied = await client.post(dispose, json={"reason": "x"}, headers=_auth(tokens["admin"]))
        assert denied.status_code == 409
        assert denied.json()["detail"]["code"] == "evidence_legal_hold_active"
        if release_id:
            released = await client.post(
                f"{holds}/{release_id}/release", json={"reason": "matter closed"},
                headers=_auth(tokens["admin"]),
            )
            assert released.status_code == 200
            assert released.json()["hold"]["status"] == "released"

    view = await client.get(f"/evidence/vault/records/{record['id']}", headers=_auth(tokens["reader"]))
    assert view.json()["legal_hold_active"] is True  # the record hold remains
    record_hold_id = record_hold.json()["hold"]["id"]
    assert (
        await client.post(f"{holds}/{record_hold_id}/release", json={"reason": "x"}, headers=_auth(tokens["other"]))
    ).status_code == 404
    released = await client.post(
        f"{holds}/{record_hold_id}/release", json={"reason": "done"}, headers=_auth(tokens["admin"])
    )
    assert released.status_code == 200
    twice = await client.post(
        f"{holds}/{record_hold_id}/release", json={"reason": "done"}, headers=_auth(tokens["admin"])
    )
    assert twice.status_code == 409
    assert twice.json()["detail"]["code"] == "legal_hold_not_active"

    # A released scope can be held again (history is kept, not overwritten).
    again = await client.post(holds, json=tenant_hold_body, headers=_auth(tokens["admin"]))
    assert again.status_code == 201
    await client.post(f"{holds}/{again.json()['hold']['id']}/release", json={"reason": "x"}, headers=_auth(tokens["admin"]))

    assert (await client.post(dispose, json={"reason": "x"}, headers=_auth(tokens["admin"]))).status_code == 200
    listed = await client.get(holds, params={"organization_id": ids["a"]}, headers=_auth(tokens["reader"]))
    assert len(listed.json()["items"]) == 3
    assert {item["status"] for item in listed.json()["items"]} == {"released"}
    assert (await client.get(holds, headers=_auth(tokens["other"]))).json()["items"] == []


@pytest.mark.asyncio
async def test_packages_stored_under_a_tenant_hold_are_held_from_the_start(vault):
    client, ids, tokens, _vault_dir = vault
    await client.post(
        "/evidence/legal-holds", json={"organization_id": ids["a"], "reason": "litigation"},
        headers=_auth(tokens["admin"]),
    )
    stored = await _store(client, tokens, ids["a"])
    assert stored.json()["record"]["legal_hold_active"] is True
    assert (await _events("evidence_vault.stored"))[-1].detail["legal_hold"] is True
    await _expire_retention(stored.json()["record"]["id"])
    denied = await client.post(
        f"/evidence/vault/records/{stored.json()['record']['id']}/dispose",
        json={"reason": "x"}, headers=_auth(tokens["admin"]),
    )
    assert denied.json()["detail"]["code"] == "evidence_legal_hold_active"


# --------------------------------------------------------------------------- #
# Tamper, absence, and recovery
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_tampered_missing_and_receipt_edits_are_detected(vault):
    client, ids, tokens, vault_dir = vault
    record = (await _store(client, tokens, ids["a"])).json()["record"]
    verify = f"/evidence/vault/records/{record['id']}/verify"
    path = vault_dir / ids["a"] / f"evidence-package-{record['package_id']}.zip"

    ok = await client.post(verify, headers=_auth(tokens["reader"]))
    assert ok.json()["integrity_state"] == "intact"

    original = path.read_bytes()
    path.chmod(0o644)
    path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
    tampered = await client.post(verify, headers=_auth(tokens["reader"]))
    assert tampered.json()["integrity_state"] == "tampered"
    assert tampered.json()["last_verify_error"] == "content_digest_mismatch"
    refused = await client.get(f"/evidence/vault/records/{record['id']}/content", headers=_auth(tokens["reader"]))
    assert refused.status_code == 409
    assert refused.json()["detail"] == {"code": "evidence_integrity_failed", "state": "tampered"}

    path.unlink()
    missing = await client.post(verify, headers=_auth(tokens["reader"]))
    assert missing.json()["integrity_state"] == "missing"

    path.write_bytes(original)
    async with AsyncSessionLocal() as db:
        row = await db.get(EvidenceVaultRecord, record["id"])
        row.storage_receipt = {**row.storage_receipt, "sha256": "0" * 64}
        await db.commit()
    edited = await client.post(verify, headers=_auth(tokens["reader"]))
    assert edited.json()["integrity_state"] == "tampered"
    assert edited.json()["last_verify_error"] == "receipt_digest_mismatch"
    assert edited.json()["receipt_intact"] is False
    states = [event.detail["integrity_state"] for event in await _events("evidence_vault.verified")]
    assert states == ["intact", "tampered", "missing", "tampered"]

    status = (await client.get("/evidence/vault/status", headers=_auth(tokens["reader"]))).json()
    assert status["integrity_failures"] == 1
    assert status["alert"] is True


@pytest.mark.asyncio
async def test_object_conflict_and_database_loss_recovery(vault):
    client, ids, tokens, vault_dir = vault
    record = (await _store(client, tokens, ids["a"])).json()["record"]
    path = vault_dir / ids["a"] / f"evidence-package-{record['package_id']}.zip"

    # Lost database row: the content-addressed object is still there, and a
    # re-store of the same pinned package reconciles onto it byte-for-byte.
    async with AsyncSessionLocal() as db:
        await db.execute(delete(EvidenceVaultRecord))
        await db.commit()
    recovered = await _store(client, tokens, ids["a"], through_seq=record["through_seq"])
    assert recovered.status_code == 201, recovered.text
    assert recovered.json()["record"]["sha256"] == record["sha256"]

    # Different bytes at the same key means substitution: refuse, never overwrite.
    async with AsyncSessionLocal() as db:
        await db.execute(delete(EvidenceVaultRecord))
        await db.commit()
    path.chmod(0o644)
    path.write_bytes(b"not the package")
    conflict = await _store(client, tokens, ids["a"], through_seq=record["through_seq"])
    assert conflict.status_code == 409
    assert conflict.json()["detail"] == {"code": "evidence_object_conflict", "state": "tampered"}
    assert path.read_bytes() == b"not the package"
    failed = await _events("evidence_vault.store_failed")
    assert failed[-1].detail["code"] == "evidence_object_conflict"


# --------------------------------------------------------------------------- #
# S3 Object Lock
# --------------------------------------------------------------------------- #
@pytest.fixture
def s3_vault(monkeypatch):
    with mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(
            Bucket=_BUCKET, ObjectLockEnabledForBucket=True
        )
        monkeypatch.setattr(settings, "evidence_vault_backend", "s3")
        monkeypatch.setattr(settings, "evidence_vault_s3_bucket", _BUCKET)
        monkeypatch.setattr(settings, "evidence_vault_s3_region", "us-east-1")
        monkeypatch.setattr(settings, "evidence_vault_s3_object_lock_mode", "COMPLIANCE")
        yield boto3.client("s3", region_name="us-east-1")


def _head(s3, record: dict) -> dict:
    receipt = record["storage_receipt"]
    return s3.head_object(Bucket=_BUCKET, Key=receipt["key"], VersionId=receipt["version_id"])


@pytest.mark.asyncio
async def test_s3_object_lock_enforces_retention_and_legal_hold(vault, s3_vault):
    client, ids, tokens, _vault_dir = vault
    s3 = s3_vault
    stored = await _store(client, tokens, ids["a"])
    assert stored.status_code == 201, stored.text
    record = stored.json()["record"]
    receipt = record["storage_receipt"]
    assert record["retention_mode"] == "COMPLIANCE"
    assert receipt["version_id"] and receipt["bucket"] == _BUCKET
    blob = json.dumps(receipt).lower()
    for marker in ("secret", "access_key", "password", "token", "signature="):
        assert marker not in blob
    head = _head(s3, record)
    assert head["ObjectLockMode"] == "COMPLIANCE"
    assert head["ObjectLockLegalHoldStatus"] == "OFF"

    # The storage itself refuses deletion, independent of NodeLink.
    with pytest.raises(Exception) as refused:
        s3.delete_object(Bucket=_BUCKET, Key=receipt["key"], VersionId=receipt["version_id"])
    assert "AccessDenied" in str(refused.value)

    hold = await client.post(
        "/evidence/legal-holds",
        json={"organization_id": ids["a"], "record_id": record["id"], "reason": "matter 7"},
        headers=_auth(tokens["admin"]),
    )
    assert hold.json()["storage_synced"] == 1
    assert _head(s3, record)["ObjectLockLegalHoldStatus"] == "ON"
    await client.post(
        f"/evidence/legal-holds/{hold.json()['hold']['id']}/release",
        json={"reason": "closed"}, headers=_auth(tokens["admin"]),
    )
    assert _head(s3, record)["ObjectLockLegalHoldStatus"] == "OFF"

    # NodeLink's ledger says retention elapsed, but storage disagrees: the
    # storage wins and the drift is surfaced.
    await _expire_retention(record["id"])
    drift = await client.post(
        f"/evidence/vault/records/{record['id']}/dispose", json={"reason": "x"},
        headers=_auth(tokens["admin"]),
    )
    assert drift.status_code == 409
    assert drift.json()["detail"]["code"] == "evidence_storage_refused_deletion"
    view = await client.get(f"/evidence/vault/records/{record['id']}", headers=_auth(tokens["reader"]))
    assert view.json()["integrity_state"] == "lock_drift"
    assert _head(s3, record)["ContentLength"] == record["size_bytes"]


@pytest.mark.asyncio
async def test_s3_disposal_after_real_expiry_and_lock_weakening(vault, s3_vault):
    _client, ids, _tokens, _vault_dir = vault
    s3 = s3_vault
    vault_backend = evidence_vault.require_vault()
    async with AsyncSessionLocal() as db:
        tenant = await db.get(Client, ids["a"])
        artifact = await evidence_bundles.build_bundle(db, tenant=tenant)
        package = evidence_packages.build_signed_package(artifact)
        # Retention that elapses in seconds: stored "almost a day ago".
        outcome = await evidence_vault.store_package(
            db, vault_backend, client_id=tenant.id, artifact=artifact, from_seq=1,
            package=package, retention_days=1, operator_id=None, operator_email="t@x",
            now=datetime.now(timezone.utc) - timedelta(days=1) + timedelta(seconds=2),
        )
        await db.commit()
        record_id = outcome.record.id
    time.sleep(3)
    async with AsyncSessionLocal() as db:
        record = await db.get(EvidenceVaultRecord, record_id)
        await evidence_vault.dispose_record(db, vault_backend, record, operator_email="t@x")
        await db.commit()
        receipt = record.storage_receipt
    with pytest.raises(Exception) as gone:
        s3.head_object(Bucket=_BUCKET, Key=receipt["key"], VersionId=receipt["version_id"])
    assert "404" in str(gone.value)

    # A record claiming a longer lock than storage holds is lock drift.
    async with AsyncSessionLocal() as db:
        artifact = await evidence_bundles.build_bundle(db, tenant=await db.get(Client, ids["b"]))
        package = evidence_packages.build_signed_package(artifact)
        outcome = await evidence_vault.store_package(
            db, vault_backend, client_id=ids["b"], artifact=artifact, from_seq=1,
            package=package, retention_days=30, operator_id=None, operator_email="t@x",
        )
        outcome.record.retain_until = outcome.record.retain_until + timedelta(days=365)
        result = await evidence_vault.verify_record(db, vault_backend, outcome.record)
        assert (result.integrity_state, result.reason) == ("lock_drift", "retention_shortened")
        await db.rollback()


@pytest.mark.asyncio
async def test_s3_bucket_without_object_lock_fails_closed(vault, s3_vault, monkeypatch):
    client, ids, tokens, _vault_dir = vault
    s3_vault.create_bucket(Bucket="nodelink-unlocked")
    monkeypatch.setattr(settings, "evidence_vault_s3_bucket", "nodelink-unlocked")
    response = await _store(client, tokens, ids["a"])
    assert response.status_code == 503
    assert response.json()["detail"] == {"code": "evidence_vault_misconfigured", "state": "unavailable"}
    async with AsyncSessionLocal() as db:
        assert (await db.execute(select(EvidenceVaultRecord))).scalars().all() == []
    assert (await _events("evidence_vault.store_failed"))[-1].detail["code"] == "evidence_vault_misconfigured"


@pytest.mark.asyncio
async def test_storage_outage_fails_store_closed_but_never_loses_a_hold(vault, s3_vault, monkeypatch):
    client, ids, tokens, _vault_dir = vault
    s3 = s3_vault
    record = (await _store(client, tokens, ids["a"])).json()["record"]

    def outage(*_args, **_kwargs):
        raise evidence_vault.BackendUnavailable("s3 put_object failed: ServiceUnavailable")

    monkeypatch.setattr(evidence_vault.S3Vault, "put", outage)
    monkeypatch.setattr(evidence_vault.S3Vault, "set_legal_hold", outage)
    monkeypatch.setattr(evidence_vault.S3Vault, "get", outage)

    down = await _store(client, tokens, ids["a"], through_seq=1)
    assert down.status_code == 503
    assert down.json()["detail"] == {"code": "evidence_vault_unavailable", "state": "unavailable"}

    hold = await client.post(
        "/evidence/legal-holds", json={"organization_id": ids["a"], "reason": "preserve"},
        headers=_auth(tokens["admin"]),
    )
    assert hold.status_code == 201
    assert hold.json()["storage_pending"] == 1
    status = (await client.get("/evidence/vault/status", headers=_auth(tokens["reader"]))).json()
    assert status["storage_hold_reconciliation_pending"] == 1
    assert status["alert"] is True
    unreachable = await client.post(
        f"/evidence/vault/records/{record['id']}/verify", headers=_auth(tokens["reader"])
    )
    assert unreachable.json()["integrity_state"] == "unavailable"  # not "tampered"
    # The hold row blocks disposal even though storage never saw the hold.
    await _expire_retention(record["id"])
    denied = await client.post(
        f"/evidence/vault/records/{record['id']}/dispose", json={"reason": "x"},
        headers=_auth(tokens["admin"]),
    )
    assert denied.json()["detail"]["code"] == "evidence_legal_hold_active"

    monkeypatch.undo()
    # monkeypatch.undo() also reverted the vault settings; restore them.
    monkeypatch.setattr(settings, "evidence_vault_backend", "s3")
    monkeypatch.setattr(settings, "evidence_vault_s3_bucket", _BUCKET)
    monkeypatch.setattr(settings, "evidence_vault_s3_region", "us-east-1")
    async with AsyncSessionLocal() as db:
        result = await evidence_vault.sweep(db, evidence_vault.require_vault(), settings)
        await db.commit()
    assert result.holds_reconciled == 1
    assert _head(s3, record)["ObjectLockLegalHoldStatus"] == "ON"
    status = (await client.get("/evidence/vault/status", headers=_auth(tokens["reader"]))).json()
    assert status["storage_hold_reconciliation_pending"] == 0


@pytest.mark.asyncio
async def test_sweep_audits_only_transitions_into_failure(vault, monkeypatch):
    from app.core import tasks

    client, ids, tokens, vault_dir = vault
    record = (await _store(client, tokens, ids["a"])).json()["record"]
    path = vault_dir / ids["a"] / f"evidence-package-{record['package_id']}.zip"

    await tasks._vault_sweep_once()
    assert await _events("evidence_vault.verified") == []  # intact -> intact is silent

    path.chmod(0o644)
    path.write_bytes(b"replaced")
    await tasks._vault_sweep_once()
    await tasks._vault_sweep_once()
    swept = await _events("evidence_vault.verified")
    assert len(swept) == 1
    assert swept[0].actor == "system"
    assert swept[0].detail["trigger"] == "sweep"
    assert swept[0].detail["integrity_state"] == "tampered"
    async with AsyncSessionLocal() as db:
        holds = (await db.execute(select(EvidenceLegalHold))).scalars().all()
    assert holds == []
