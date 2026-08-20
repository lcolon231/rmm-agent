# SPDX-License-Identifier: AGPL-3.0-only
"""Security and reproducibility tests for evidence bundles (issue #79)."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_evidence_bundles.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")
_READER_PW = os.environ.setdefault("NODELINK_TEST_EVIDENCE_READER_PW", "reader-pw")
_OTHER_PW = os.environ.setdefault("NODELINK_TEST_EVIDENCE_OTHER_PW", "other-pw")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)
from sqlalchemy import select  # noqa: E402

from app.core import (  # noqa: E402
    anchor,
    anchor_publish,
    audit,
    evidence_bundles,
    evidence_packages,
)
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.keyring import active_signing_key  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    Agent,
    AnchorPublication,
    AuditAnchor,
    AuditEvent,
    Client,
    ClientRole,
    Command,
    CommandKind,
    CommandStatus,
    MonitoringPolicy,
    MonitoringPolicyRevision,
    MonitoringScope,
    Operator,
    OperatorClientMembership,
    OperatorRole,
    Site,
)

_SENTINEL = os.environ.setdefault(
    "NODELINK_TEST_EVIDENCE_SENSITIVE_VALUE", "never-export-sensitive-value"
)
_CONTRACT_ROOT = Path(__file__).resolve().parents[2] / "contracts"


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _trusted_public_key() -> bytes:
    return active_signing_key().public_key_pem.encode("ascii")


def _rewrite_package(
    payload: bytes,
    *,
    replacements: dict[str, bytes] | None = None,
    renamed_path: tuple[str, str] | None = None,
) -> bytes:
    members = evidence_packages.read_archive(payload)
    replacements = replacements or {}
    entries = []
    for path in evidence_packages.ARCHIVE_PATHS:
        output_path = (
            renamed_path[1]
            if renamed_path is not None and path == renamed_path[0]
            else path
        )
        entries.append((output_path, replacements.get(path, members[path])))
    return evidence_packages.serialize_archive(entries)


@pytest_asyncio.fixture
async def evidence_tenancy():
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)

    now = datetime(2026, 8, 20, 4, 0, tzinfo=timezone.utc)
    async with AsyncSessionLocal() as db:
        reader = Operator(
            email="evidence-reader@nodelink.test",
            password_hash=hash_password(_READER_PW),
            role=OperatorRole.readonly,
        )
        other = Operator(
            email="evidence-other@nodelink.test",
            password_hash=hash_password(_OTHER_PW),
            role=OperatorRole.readonly,
        )
        tenant_a = Client(name="Alpha Evidence")
        tenant_b = Client(name="Bravo Evidence")
        db.add_all([reader, other, tenant_a, tenant_b])
        await db.flush()

        site_a = Site(client_id=tenant_a.id, name="Alpha HQ", created_at=now)
        site_b = Site(client_id=tenant_b.id, name="Bravo HQ", created_at=now)
        db.add_all([site_a, site_b])
        await db.flush()
        agent_a = Agent(
            site_id=site_a.id,
            token_hash="a" * 64,
            name="Alpha endpoint",
            hostname="alpha-host",
            os="windows",
            os_version="11",
            agent_version="0.1.7",
            architecture="amd64",
            labels=["regulated", f"password={_SENTINEL}"],
            command_envelope_versions=["command-v3"],
            status="online",
            enrolled_at=now,
        )
        agent_b = Agent(
            site_id=site_b.id,
            token_hash="b" * 64,
            name="Bravo endpoint",
            hostname="bravo-host",
            os="windows",
            architecture="amd64",
            enrolled_at=now,
        )
        db.add_all([agent_a, agent_b])
        await db.flush()
        db.add_all(
            [
                OperatorClientMembership(
                    operator_id=reader.id,
                    client_id=tenant_a.id,
                    role=ClientRole.client_readonly,
                    granted_by="seed",
                    reason="evidence reader",
                    created_at=now,
                ),
                OperatorClientMembership(
                    operator_id=other.id,
                    client_id=tenant_b.id,
                    role=ClientRole.client_readonly,
                    granted_by="seed",
                    reason="other reader",
                    created_at=now,
                ),
            ]
        )

        policy = MonitoringPolicy(
            name="Alpha baseline",
            scope=MonitoringScope.client,
            scope_id=tenant_a.id,
            enabled=True,
            created_at=now,
        )
        db.add(policy)
        await db.flush()
        db.add(
            MonitoringPolicyRevision(
                policy_id=policy.id,
                version=1,
                checks=[
                    {"key": "disk", "type": "disk", "api_token": _SENTINEL}
                ],
                change_note=_SENTINEL,
                created_by=reader.email,
                created_at=now,
            )
        )

        await audit.record(
            db,
            action="agent.offline",
            actor=reader.email,
            actor_user_id=reader.id,
            agent_id=agent_a.id,
            organization_id=tenant_a.id,
            detail={"last_seen_at": now.isoformat()},
        )
        await audit.record(
            db,
            action="agent.offline",
            actor=other.email,
            actor_user_id=other.id,
            agent_id=agent_b.id,
            organization_id=tenant_b.id,
            detail={"last_seen_at": now.isoformat()},
        )

        command_id = str(uuid4())
        command = Command(
            id=command_id,
            agent_id=agent_a.id,
            kind=CommandKind.scan_updates,
            payload={"api_token": _SENTINEL, "mode": "scan"},
            envelope_version="command-v3",
            schema_version=1,
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
            nonce="A" * 24,
            signing_key_id="default",
            signature="c2lnbmF0dXJl",
            status=CommandStatus.succeeded,
            exit_code=0,
            stdout=f"result {_SENTINEL}",
            stderr=f"warning {_SENTINEL}",
            stdout_truncated=False,
            stderr_truncated=False,
            stdout_total_bytes=24,
            stderr_total_bytes=25,
            created_at=now,
            dispatched_at=now,
            completed_at=now + timedelta(seconds=3),
            actor_email=reader.email,
            actor_operator_id=reader.id,
            attempt=1,
        )
        db.add(command)
        await db.flush()
        envelope_sha256 = hashlib.sha256(b"canonical-secret-bearing-envelope").hexdigest()
        dispatched = await audit.record(
            db,
            action="command.dispatched",
            actor=reader.email,
            actor_user_id=reader.id,
            agent_id=agent_a.id,
            organization_id=tenant_a.id,
            detail={
                "command_id": command.id,
                "kind": command.kind.value,
                "payload_keys": sorted(command.payload),
                "envelope_version": command.envelope_version,
                "schema_version": command.schema_version,
                "issued_at": "2026-08-20T04:00:00Z",
                "expires_at": "2026-08-20T04:05:00Z",
                "nonce": command.nonce,
                "signing_key_id": command.signing_key_id,
                "envelope_sha256": envelope_sha256,
                "script_version_id": None,
                "script_parameter_value_set_id": None,
            },
        )
        command.dispatch_audit_event_id = dispatched.id
        await db.flush()
        await audit.record(
            db,
            action="command.completed",
            actor="agent",
            agent_id=agent_a.id,
            organization_id=tenant_a.id,
            detail={
                "command_id": command.id,
                "kind": command.kind.value,
                "exit_code": 0,
                "status": "succeeded",
                "agent_completed_at": None,
                "stdout_truncated": False,
                "stderr_truncated": False,
                "stdout_total_bytes": 24,
                "stderr_total_bytes": 25,
            },
        )
        created_anchor = await anchor.create_anchor(db)
        assert created_anchor is not None
        receipt = {
            "backend": "filesystem",
            "path": "immutable/anchor.json",
            "sha256": "c" * 64,
            "bytes": 256,
        }
        publication = AnchorPublication(
            anchor_id=created_anchor.id,
            backend="filesystem",
            status="published",
            uri="file://immutable/anchor.json",
            receipt=receipt,
            receipt_sha256=anchor_publish.receipt_digest(receipt),
            attempts=1,
            published_at=now,
        )
        db.add(publication)
        await db.commit()
        ids = {
            "tenant_a": tenant_a.id,
            "tenant_b": tenant_b.id,
            "agent_a": agent_a.id,
            "agent_b": agent_b.id,
            "command": command.id,
            "anchor": created_anchor.id,
            "publication": publication.id,
        }

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test/api/v1"
    ) as client:
        reader_login = await client.post(
            "/auth/login",
            json={"email": "evidence-reader@nodelink.test", "password": _READER_PW},
        )
        other_login = await client.post(
            "/auth/login",
            json={"email": "evidence-other@nodelink.test", "password": _OTHER_PW},
        )
        assert reader_login.status_code == other_login.status_code == 200
        yield client, ids, {
            "reader": reader_login.json()["access_token"],
            "other": other_login.json()["access_token"],
        }
    await engine.dispose()


@pytest.mark.asyncio
async def test_json_export_is_tenant_scoped_redacted_and_verifiable(evidence_tenancy):
    client, ids, tokens = evidence_tenancy
    response = await client.get(
        "/evidence/bundles/export",
        params={"organization_id": ids["tenant_a"], "format": "json"},
        headers=_auth(tokens["reader"]),
    )
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-type"].startswith(
        evidence_bundles.JSON_MEDIA_TYPE
    )
    document = response.json()
    evidence_bundles.verify_bundle_document(document)
    assert response.headers["x-nodelink-evidence-bundle-id"] == document["manifest"]["bundle_id"]

    serialized = response.content.decode("utf-8")
    assert _SENTINEL not in serialized
    assert ids["tenant_b"] not in serialized
    assert ids["agent_b"] not in serialized
    assert document["records"]["tenant"] == [
        {
            "created_at": document["records"]["tenant"][0]["created_at"],
            "name": "Alpha Evidence",
            "tenant_id": ids["tenant_a"],
        }
    ]
    assert [
        item["command_id"] for item in document["records"]["signed_actions"]
    ] == [ids["command"]]
    action = document["records"]["signed_actions"][0]
    assert action["payload_state"] == "withheld_sensitive"
    assert "payload" not in action
    result = document["records"]["results"][0]
    assert result["stdout"]["state"] == "withheld_sensitive"
    assert result["stderr"]["state"] == "withheld_sensitive"
    assert document["manifest"]["verification"]["audit_chain"]["state"] == "intact"
    assert document["manifest"]["verification"]["anchor"]["state"] == "verified"

    async with AsyncSessionLocal() as db:
        export_event = (
            await db.execute(
                select(AuditEvent).where(AuditEvent.action == "evidence_bundle.exported")
            )
        ).scalar_one()
        assert export_event.organization_id == ids["tenant_a"]
        assert export_event.detail["bundle_id"] == document["manifest"]["bundle_id"]


@pytest.mark.asyncio
async def test_pinned_json_and_csv_are_deterministic_and_clean_room_verifiable(
    evidence_tenancy, tmp_path: Path
):
    client, ids, tokens = evidence_tenancy
    params = {"organization_id": ids["tenant_a"], "format": "json"}
    first = await client.get(
        "/evidence/bundles/export", params=params, headers=_auth(tokens["reader"])
    )
    assert first.status_code == 200, first.text
    through_seq = first.headers["x-nodelink-audit-through-seq"]
    pinned = {**params, "through_seq": through_seq}
    second = await client.get(
        "/evidence/bundles/export", params=pinned, headers=_auth(tokens["reader"])
    )
    assert second.status_code == 200, second.text
    assert first.content == second.content

    csv_response = await client.get(
        "/evidence/bundles/export",
        params={**pinned, "format": "csv"},
        headers=_auth(tokens["reader"]),
    )
    assert csv_response.status_code == 200, csv_response.text
    reconstructed = evidence_bundles.parse_csv(csv_response.content)
    evidence_bundles.verify_bundle_document(reconstructed)
    assert reconstructed == first.json()
    with pytest.raises(
        evidence_bundles.EvidenceVerificationError,
        match="not canonically encoded",
    ):
        evidence_bundles.parse_csv(csv_response.content.replace(b"\n", b"\r\n"))

    verifier = Path(__file__).resolve().parents[1] / "scripts" / "verify_evidence_bundle.py"
    for name, payload in (("bundle.json", first.content), ("bundle.csv", csv_response.content)):
        artifact = tmp_path / name
        artifact.write_bytes(payload)
        checked = subprocess.run(
            [sys.executable, str(verifier), str(artifact)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert checked.returncode == 0, checked.stderr
        assert "verify-evidence: OK" in checked.stdout

    tampered = copy.deepcopy(first.json())
    tampered["records"]["tenant"][0]["name"] = "Changed"
    with pytest.raises(evidence_bundles.EvidenceVerificationError, match="digest mismatch"):
        evidence_bundles.verify_bundle_document(tampered)


@pytest.mark.asyncio
async def test_cross_tenant_and_invalid_or_unavailable_states_fail_closed(evidence_tenancy):
    client, ids, tokens = evidence_tenancy
    denied = await client.get(
        "/evidence/bundles/export",
        params={"organization_id": ids["tenant_b"]},
        headers=_auth(tokens["reader"]),
    )
    assert denied.status_code == 404

    invalid = await client.get(
        "/evidence/bundles/export",
        params={"organization_id": ids["tenant_a"], "from_seq": 8, "through_seq": 2},
        headers=_auth(tokens["reader"]),
    )
    assert invalid.status_code == 422
    assert invalid.json()["detail"]["code"] == "evidence_sequence_range_invalid"

    unavailable = await client.get(
        "/evidence/bundles/export",
        params={"organization_id": ids["tenant_a"], "through_seq": 999999},
        headers=_auth(tokens["reader"]),
    )
    assert unavailable.status_code == 409
    assert unavailable.json()["detail"] == {
        "code": "evidence_snapshot_unavailable",
        "state": "unavailable",
    }

    limited = await client.get(
        "/evidence/bundles/export",
        params={"organization_id": ids["tenant_a"], "record_limit": 1},
        headers=_auth(tokens["reader"]),
    )
    assert limited.status_code == 413
    assert limited.json()["detail"]["state"] == "limit_exceeded"


@pytest.mark.asyncio
async def test_chain_and_anchor_tampering_are_refused(evidence_tenancy):
    client, ids, tokens = evidence_tenancy
    async with AsyncSessionLocal() as db:
        event = (
            await db.execute(
                select(AuditEvent)
                .where(AuditEvent.organization_id == ids["tenant_a"])
                .order_by(AuditEvent.seq)
            )
        ).scalars().first()
        assert event is not None
        event.detail = {**event.detail, "last_seen_at": "tampered"}
        await db.commit()
    response = await client.get(
        "/evidence/bundles/export",
        params={"organization_id": ids["tenant_a"]},
        headers=_auth(tokens["reader"]),
    )
    assert response.status_code == 409
    assert response.json()["detail"] == {
        "code": "audit_chain_not_intact",
        "state": "tampered",
    }


@pytest.mark.asyncio
async def test_anchor_tampering_is_refused_even_with_an_intact_chain(evidence_tenancy):
    client, ids, tokens = evidence_tenancy
    async with AsyncSessionLocal() as db:
        stored_anchor = await db.get(AuditAnchor, ids["anchor"])
        assert stored_anchor is not None
        stored_anchor.merkle_root = "f" * 64
        await db.commit()
    response = await client.get(
        "/evidence/bundles/export",
        params={"organization_id": ids["tenant_a"]},
        headers=_auth(tokens["reader"]),
    )
    assert response.status_code == 409
    assert response.json()["detail"] == {
        "code": "audit_anchor_not_intact",
        "state": "tampered",
    }


@pytest.mark.asyncio
async def test_published_anchor_with_missing_receipt_is_refused(evidence_tenancy):
    client, ids, tokens = evidence_tenancy
    async with AsyncSessionLocal() as db:
        publication = await db.get(AnchorPublication, ids["publication"])
        assert publication is not None
        publication.receipt = None
        publication.receipt_sha256 = None
        await db.commit()
    response = await client.get(
        "/evidence/bundles/export",
        params={"organization_id": ids["tenant_a"]},
        headers=_auth(tokens["reader"]),
    )
    assert response.status_code == 409
    assert response.json()["detail"] == {
        "code": "anchor_receipt_not_intact",
        "state": "tampered",
    }


def test_large_logical_export_has_stable_bytes_and_digests():
    records = {name: [] for name in evidence_bundles.SECTION_ORDER}
    records["tenant"] = [{"tenant_id": "tenant-large", "name": "Large"}]
    records["audit_hashes"] = [
        {
            "seq": seq,
            "event_id": f"event-{seq:05d}",
            "event_hash": f"{seq:064x}",
        }
        for seq in range(1, 2501)
    ]
    artifact = evidence_bundles._build_document(
        tenant_id="tenant-large",
        from_seq=1,
        through_seq=2500,
        snapshot_event_hash=f"{2500:064x}",
        snapshot_at="2026-08-20T04:00:00+00:00",
        records=records,
        verification={
            "audit_chain": {
                "state": "intact",
                "through_seq": 2500,
                "selected_event_count": 0,
            },
            "anchor": {
                "state": "unavailable",
                "coverage_through_seq": 0,
                "unanchored_event_count": 2500,
                "publication_state": "unavailable",
            },
            "command_signatures": {
                "state": "available",
                "missing_key_ids": [],
                "legacy_unkeyed_count": 0,
                "payload_verification": "metadata_only_payload_withheld",
            },
            "redaction": {
                "audit_details": "stored_sanitized_representation",
                "command_payloads": "withheld_sensitive",
                "command_outputs": "withheld_sensitive",
                "policy_free_text": "digest_only",
            },
        },
    )
    first = evidence_bundles.serialize_json(artifact)
    second = evidence_bundles.serialize_json(artifact)
    assert first == second
    assert len(first) > 250_000
    evidence_bundles.verify_bundle_document(artifact.document)

    pdf = evidence_packages.render_pdf(artifact)
    evidence_packages.verify_pdf(pdf, expected_bundle_id=artifact.bundle_id)
    package = evidence_packages.build_signed_package(artifact)
    verified = evidence_packages.verify_signed_package(
        package.content,
        trusted_public_key_pem=_trusted_public_key(),
    )
    assert verified.package_id == package.package_id
    assert evidence_packages.build_signed_package(artifact).content == package.content
    with pytest.raises(
        evidence_packages.EvidencePackageError,
        match="evidence_package_size_exceeded",
    ):
        evidence_packages.build_signed_package(artifact, max_archive_bytes=1024)


def test_golden_v1_contract_vector_and_schema_are_stable():
    vector = json.loads(
        (_CONTRACT_ROOT / "test-vectors" / "evidence-bundle-v1.json").read_text(
            encoding="utf-8"
        )
    )
    schema = json.loads(
        (_CONTRACT_ROOT / "evidence-bundle-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    evidence_bundles.verify_bundle_document(vector)
    assert vector["manifest"]["bundle_id"] == (
        "4acf1ab45c501a24e72bd6b329a4d806f106f7b26fd742e1401bc4c09f8871ed"
    )
    assert schema["properties"]["version"]["const"] == evidence_bundles.VERSION
    assert set(schema["properties"]["records"]["required"]) == set(
        evidence_bundles.SECTION_ORDER
    )

    package_vector = json.loads(
        (_CONTRACT_ROOT / "test-vectors" / "evidence-package-v1.json").read_text(
            encoding="utf-8"
        )
    )
    package_schema = json.loads(
        (_CONTRACT_ROOT / "evidence-package-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    package_base = {
        key: value for key, value in package_vector.items() if key != "package_id"
    }
    assert package_vector["package_id"] == hashlib.sha256(
        evidence_bundles.canonical_json(package_base)
    ).hexdigest()
    assert package_vector["package_id"] == (
        "be010c14b5dda5478b5bc20a3a4a677bdb330dfed7f987c964659ba941b807ad"
    )
    assert package_schema["properties"]["version"]["const"] == (
        evidence_packages.PACKAGE_VERSION
    )
    assert [item["path"] for item in package_vector["files"]] == list(
        evidence_packages.CONTENT_PATHS
    )


@pytest.mark.asyncio
async def test_pdf_export_is_accessible_redacted_and_pinned(evidence_tenancy):
    client, ids, tokens = evidence_tenancy
    first = await client.get(
        "/evidence/bundles/export",
        params={"organization_id": ids["tenant_a"], "format": "pdf"},
        headers=_auth(tokens["reader"]),
    )
    assert first.status_code == 200, first.text
    assert first.headers["content-type"].startswith(evidence_packages.PDF_MEDIA_TYPE)
    bundle_id = first.headers["x-nodelink-evidence-bundle-id"]
    evidence_packages.verify_pdf(first.content, expected_bundle_id=bundle_id)
    assert b"/StructTreeRoot" in first.content
    assert b"/MarkInfo << /Marked true >>" in first.content
    assert b"/Lang (en-US)" in first.content
    assert b"Alpha Evidence" in first.content
    assert _SENTINEL.encode() not in first.content
    assert ids["tenant_b"].encode() not in first.content

    pinned = await client.get(
        "/evidence/bundles/export",
        params={
            "organization_id": ids["tenant_a"],
            "format": "pdf",
            "through_seq": first.headers["x-nodelink-audit-through-seq"],
        },
        headers=_auth(tokens["reader"]),
    )
    assert pinned.status_code == 200, pinned.text
    assert pinned.content == first.content


@pytest.mark.asyncio
async def test_signed_zip_is_complete_deterministic_and_clean_room_verifiable(
    evidence_tenancy, tmp_path: Path
):
    client, ids, tokens = evidence_tenancy
    first = await client.get(
        "/evidence/bundles/export",
        params={"organization_id": ids["tenant_a"], "format": "zip"},
        headers=_auth(tokens["reader"]),
    )
    assert first.status_code == 200, first.text
    assert first.headers["content-type"].startswith(evidence_packages.ZIP_MEDIA_TYPE)
    package_id = first.headers["x-nodelink-evidence-package-id"]
    verified = evidence_packages.verify_signed_package(
        first.content,
        trusted_public_key_pem=_trusted_public_key(),
    )
    assert verified.package_id == package_id
    assert verified.bundle_id == first.headers["x-nodelink-evidence-bundle-id"]
    assert verified.trusted_key_matched is True
    assert _SENTINEL.encode() not in first.content
    assert ids["tenant_b"].encode() not in first.content

    members = evidence_packages.read_archive(first.content)
    assert tuple(members) == evidence_packages.ARCHIVE_PATHS
    manifest = json.loads(members[evidence_packages.MANIFEST_PATH])
    assert [item["path"] for item in manifest["files"]] == list(
        evidence_packages.CONTENT_PATHS
    )
    assert manifest["signing"]["context"] == evidence_packages.SIGNING_CONTEXT_NAME

    pinned = await client.get(
        "/evidence/bundles/export",
        params={
            "organization_id": ids["tenant_a"],
            "format": "zip",
            "through_seq": first.headers["x-nodelink-audit-through-seq"],
        },
        headers=_auth(tokens["reader"]),
    )
    assert pinned.status_code == 200, pinned.text
    assert pinned.content == first.content

    archive_path = tmp_path / "evidence.zip"
    public_key_path = tmp_path / "trusted-public.pem"
    archive_path.write_bytes(first.content)
    public_key_path.write_bytes(_trusted_public_key())
    verifier = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "verify_evidence_package.py"
    )
    checked = subprocess.run(
        [
            sys.executable,
            str(verifier),
            str(archive_path),
            "--trusted-public-key",
            str(public_key_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert checked.returncode == 0, checked.stderr
    assert "trusted-key=matched" in checked.stdout

    async with AsyncSessionLocal() as db:
        export_events = list(
            (
                await db.execute(
                    select(AuditEvent)
                    .where(AuditEvent.action == "evidence_bundle.exported")
                    .order_by(AuditEvent.seq)
                )
            ).scalars().all()
        )
    assert export_events[-1].detail["format"] == "zip"
    assert export_events[-1].detail["package_id"] == package_id
    assert export_events[-1].detail["signing_key_id"] == verified.signing_key_id


@pytest.mark.asyncio
async def test_signed_zip_tamper_traversal_and_trust_fail_closed(evidence_tenancy):
    client, ids, tokens = evidence_tenancy
    response = await client.get(
        "/evidence/bundles/export",
        params={"organization_id": ids["tenant_a"], "format": "zip"},
        headers=_auth(tokens["reader"]),
    )
    assert response.status_code == 200, response.text
    members = evidence_packages.read_archive(response.content)

    tampered_evidence = _rewrite_package(
        response.content,
        replacements={
            evidence_packages.EVIDENCE_PATH: members[evidence_packages.EVIDENCE_PATH]
            + b" "
        },
    )
    with pytest.raises(
        evidence_packages.PackageVerificationError,
        match="digest or size mismatch",
    ):
        evidence_packages.verify_signed_package(
            tampered_evidence,
            trusted_public_key_pem=_trusted_public_key(),
        )

    incomplete_manifest = json.loads(members[evidence_packages.MANIFEST_PATH])
    incomplete_manifest["files"] = incomplete_manifest["files"][:-1]
    incomplete = _rewrite_package(
        response.content,
        replacements={
            evidence_packages.MANIFEST_PATH: evidence_bundles.canonical_json(
                incomplete_manifest
            )
        },
    )
    with pytest.raises(
        evidence_packages.PackageVerificationError,
        match="incomplete or unordered",
    ):
        evidence_packages.verify_signed_package(
            incomplete,
            trusted_public_key_pem=_trusted_public_key(),
        )

    signature = json.loads(members[evidence_packages.SIGNATURE_PATH])
    signature["signature"] = (
        "A" if signature["signature"][0] != "A" else "B"
    ) + signature["signature"][1:]
    tampered_signature = _rewrite_package(
        response.content,
        replacements={
            evidence_packages.SIGNATURE_PATH: evidence_bundles.canonical_json(signature)
        },
    )
    with pytest.raises(
        evidence_packages.PackageVerificationError,
        match="signature is invalid",
    ):
        evidence_packages.verify_signed_package(
            tampered_signature,
            trusted_public_key_pem=_trusted_public_key(),
        )

    traversal = _rewrite_package(
        response.content,
        renamed_path=(evidence_packages.REPORT_PATH, "../report.pdf"),
    )
    with pytest.raises(
        evidence_packages.PackageVerificationError,
        match="archive paths or ordering",
    ):
        evidence_packages.verify_signed_package(
            traversal,
            trusted_public_key_pem=_trusted_public_key(),
        )

    wrong_public = Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(
        evidence_packages.PackageVerificationError,
        match="not the trusted key",
    ):
        evidence_packages.verify_signed_package(
            response.content,
            trusted_public_key_pem=wrong_public,
        )


@pytest.mark.asyncio
async def test_zip_signing_outage_and_unsupported_format_are_explicit(
    evidence_tenancy, monkeypatch
):
    client, ids, tokens = evidence_tenancy

    def signing_unavailable():
        raise ValueError("test signing outage")

    with monkeypatch.context() as patch:
        patch.setattr(evidence_packages, "active_signing_key", signing_unavailable)
        unavailable = await client.get(
            "/evidence/bundles/export",
            params={"organization_id": ids["tenant_a"], "format": "zip"},
            headers=_auth(tokens["reader"]),
        )
    assert unavailable.status_code == 503
    assert unavailable.json()["detail"] == {
        "code": "evidence_package_signing_unavailable",
        "state": "unavailable",
    }

    with monkeypatch.context() as patch:
        patch.setattr(evidence_packages, "render_pdf", lambda _artifact: b"not-pdf")
        invalid_pdf = await client.get(
            "/evidence/bundles/export",
            params={"organization_id": ids["tenant_a"], "format": "pdf"},
            headers=_auth(tokens["reader"]),
        )
    assert invalid_pdf.status_code == 500
    assert invalid_pdf.json()["detail"] == {
        "code": "evidence_pdf_render_failed",
        "state": "invalid",
    }

    def package_verification_failed(*_args, **_kwargs):
        raise evidence_packages.PackageVerificationError("test package failure")

    with monkeypatch.context() as patch:
        patch.setattr(
            evidence_packages,
            "verify_signed_package",
            package_verification_failed,
        )
        invalid_package = await client.get(
            "/evidence/bundles/export",
            params={"organization_id": ids["tenant_a"], "format": "zip"},
            headers=_auth(tokens["reader"]),
        )
    assert invalid_package.status_code == 500
    assert invalid_package.json()["detail"] == {
        "code": "evidence_package_verification_failed",
        "state": "invalid",
    }

    unsupported = await client.get(
        "/evidence/bundles/export",
        params={"organization_id": ids["tenant_a"], "format": "tar"},
        headers=_auth(tokens["reader"]),
    )
    assert unsupported.status_code == 422
