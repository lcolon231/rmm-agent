# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic, tenant-scoped compliance evidence bundles (issue #79).

The bundle is a computed read model: no export row or mutable staging table is
created.  A caller pins the append-only audit prefix with ``through_seq`` and
receives canonical JSON or a normalized CSV projection of the same logical
document.  Every section has a SHA-256 digest and the manifest itself is
content-addressed, so an offline verifier can detect record removal, mutation,
or reordering without access to NodeLink's database.

Sensitive command payloads and result streams are deliberately excluded.  The
bundle carries the signed-envelope digest/signature and bounded result metadata
instead.  Audit details are exported exactly as stored because they already
passed the central fail-closed redaction policy before entering the hash chain.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import anchor as anchor_core
from app.core import anchor_publish, audit
from app.core.keyring import load_keyring
from app.core.redaction import redact_detail
from app.models.models import (
    Agent,
    AnchorPublication,
    AuditAnchor,
    AuditEvent,
    Client,
    Command,
    MonitoringPolicy,
    MonitoringPolicyRevision,
    MonitoringScope,
    Operator,
    OperatorClientMembership,
    PatchApprovalPolicy,
    PatchApprovalPolicyRevision,
    Site,
)

FORMAT = "nodelink-evidence-bundle"
VERSION = 1
JSON_MEDIA_TYPE = "application/vnd.nodelink.evidence+json"
CSV_MEDIA_TYPE = "text/csv; charset=utf-8"
DEFAULT_RECORD_LIMIT = 10_000
MAX_RECORD_LIMIT = 50_000

SECTION_ORDER = (
    "tenant",
    "actors",
    "sites",
    "endpoints",
    "policies",
    "signed_actions",
    "results",
    "audit_events",
    "audit_hashes",
    "anchors",
    "verification_keys",
)
CSV_FIELDS = ("section", "ordinal", "record_sha256", "record_json")


class EvidenceBundleError(RuntimeError):
    """Stable API failure for invalid, unavailable, or tampered evidence."""

    def __init__(self, code: str, *, state: str, status_code: int):
        super().__init__(code)
        self.code = code
        self.state = state
        self.status_code = status_code


class EvidenceVerificationError(ValueError):
    """A serialized bundle failed deterministic clean-room verification."""


@dataclass(frozen=True)
class BundleArtifact:
    document: dict[str, Any]
    bundle_id: str
    through_seq: int
    total_records: int


def canonical_json(value: Any) -> bytes:
    """The only JSON encoding used for hashes and JSON response bytes."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _enum(value: Any) -> Any:
    return value.value if isinstance(value, Enum) else value


def _timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


def _safe_value(value: Any) -> Any:
    """Apply the generic deterministic credential redactor to exported data."""
    return redact_detail({"value": value})["value"]


def _digest_text(value: str | None) -> dict[str, Any]:
    if value is None:
        return {"sha256": None, "bytes": 0}
    encoded = value.encode("utf-8")
    return {"sha256": _sha256(encoded), "bytes": len(encoded)}


def _bounded(records: list[Any], limit: int, section: str) -> list[Any]:
    if len(records) > limit:
        raise EvidenceBundleError(
            "evidence_record_limit_exceeded", state="limit_exceeded", status_code=413
        )
    return records


def _build_document(
    *,
    tenant_id: str,
    from_seq: int,
    through_seq: int,
    snapshot_event_hash: str | None,
    snapshot_at: str | None,
    records: dict[str, list[dict[str, Any]]],
    verification: dict[str, Any],
) -> BundleArtifact:
    if tuple(records) != SECTION_ORDER:
        raise ValueError("evidence sections are not in canonical order")
    sections = [
        {
            "name": name,
            "record_count": len(records[name]),
            "sha256": _sha256(canonical_json(records[name])),
        }
        for name in SECTION_ORDER
    ]
    total_records = sum(section["record_count"] for section in sections)
    base_manifest = {
        "format": FORMAT,
        "version": VERSION,
        "scope": {
            "tenant_id": tenant_id,
            "from_seq": from_seq,
            "through_seq": through_seq,
            "snapshot_event_hash": snapshot_event_hash,
            "snapshot_at": snapshot_at,
        },
        "sections": sections,
        "verification": verification,
    }
    bundle_id = _sha256(canonical_json(base_manifest))
    manifest = {**base_manifest, "bundle_id": bundle_id}
    document = {
        "format": FORMAT,
        "version": VERSION,
        "manifest": manifest,
        "records": records,
    }
    return BundleArtifact(
        document=document,
        bundle_id=bundle_id,
        through_seq=through_seq,
        total_records=total_records,
    )


def serialize_json(artifact: BundleArtifact) -> bytes:
    return canonical_json(artifact.document)


def _serialize_csv_document(document: dict[str, Any]) -> bytes:
    """Normalize a logical document into deterministic long-form CSV."""
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream,
        fieldnames=CSV_FIELDS,
        lineterminator="\n",
        quoting=csv.QUOTE_ALL,
    )
    writer.writeheader()

    manifest = document["manifest"]
    manifest_json = canonical_json(manifest)
    writer.writerow(
        {
            "section": "manifest",
            "ordinal": 0,
            "record_sha256": _sha256(manifest_json),
            "record_json": manifest_json.decode("utf-8"),
        }
    )
    for section in SECTION_ORDER:
        for ordinal, record in enumerate(document["records"][section], 1):
            encoded = canonical_json(record)
            writer.writerow(
                {
                    "section": section,
                    "ordinal": ordinal,
                    "record_sha256": _sha256(encoded),
                    "record_json": encoded.decode("utf-8"),
                }
            )
    return stream.getvalue().encode("utf-8")


def serialize_csv(artifact: BundleArtifact) -> bytes:
    """Normalize a multi-section document into deterministic long-form CSV."""
    return _serialize_csv_document(artifact.document)


def parse_csv(payload: bytes) -> dict[str, Any]:
    """Reconstruct the logical JSON document from a normalized CSV artifact."""
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceVerificationError("CSV is not UTF-8") from exc
    reader = csv.DictReader(io.StringIO(text, newline=""))
    if tuple(reader.fieldnames or ()) != CSV_FIELDS:
        raise EvidenceVerificationError("CSV header does not match version 1")

    manifest: dict[str, Any] | None = None
    records = {name: [] for name in SECTION_ORDER}
    expected_ordinal = {name: 1 for name in SECTION_ORDER}
    for row in reader:
        section = row["section"]
        try:
            encoded = row["record_json"].encode("utf-8")
            if _sha256(encoded) != row["record_sha256"]:
                raise EvidenceVerificationError("CSV record digest mismatch")
            record = json.loads(row["record_json"])
            ordinal = int(row["ordinal"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            if isinstance(exc, EvidenceVerificationError):
                raise
            raise EvidenceVerificationError("malformed CSV evidence row") from exc
        if canonical_json(record) != encoded:
            raise EvidenceVerificationError("CSV record JSON is not canonical")
        if section == "manifest":
            if manifest is not None or ordinal != 0:
                raise EvidenceVerificationError("CSV manifest row is invalid")
            manifest = record
            continue
        if section not in records:
            raise EvidenceVerificationError("CSV contains an unknown section")
        if ordinal != expected_ordinal[section]:
            raise EvidenceVerificationError("CSV section ordinals are not contiguous")
        expected_ordinal[section] += 1
        records[section].append(record)
    if manifest is None:
        raise EvidenceVerificationError("CSV manifest row is missing")
    document = {
        "format": manifest.get("format"),
        "version": manifest.get("version"),
        "manifest": manifest,
        "records": records,
    }
    if _serialize_csv_document(document) != payload:
        raise EvidenceVerificationError("CSV artifact is not canonically encoded")
    return document


def verify_bundle_document(document: dict[str, Any]) -> None:
    """Verify schema shape, section digests, manifest ID, audit links, and anchor."""
    if document.get("format") != FORMAT or document.get("version") != VERSION:
        raise EvidenceVerificationError("unsupported evidence bundle format")
    manifest = document.get("manifest")
    records = document.get("records")
    if not isinstance(manifest, dict) or not isinstance(records, dict):
        raise EvidenceVerificationError("bundle manifest or records are missing")
    if set(records) != set(SECTION_ORDER) or len(records) != len(SECTION_ORDER):
        raise EvidenceVerificationError("bundle sections are missing or unknown")
    sections = manifest.get("sections")
    if not isinstance(sections, list) or [
        item.get("name") for item in sections
    ] != list(SECTION_ORDER):
        raise EvidenceVerificationError("manifest section index is invalid")
    for section in sections:
        name = section["name"]
        if section.get("record_count") != len(records[name]):
            raise EvidenceVerificationError(f"record count mismatch in {name}")
        if section.get("sha256") != _sha256(canonical_json(records[name])):
            raise EvidenceVerificationError(f"section digest mismatch in {name}")

    bundle_id = manifest.get("bundle_id")
    base_manifest = {key: value for key, value in manifest.items() if key != "bundle_id"}
    if bundle_id != _sha256(canonical_json(base_manifest)):
        raise EvidenceVerificationError("bundle ID does not match the manifest")

    hashes = records["audit_hashes"]
    expected_seq = 1
    hash_by_seq: dict[int, str] = {}
    event_id_by_seq: dict[int, str] = {}
    for item in hashes:
        if item.get("seq") != expected_seq:
            raise EvidenceVerificationError("audit hash sequence is not contiguous")
        event_hash = item.get("event_hash")
        event_id = item.get("event_id")
        if not isinstance(event_hash, str) or len(event_hash) != 64:
            raise EvidenceVerificationError("audit hash is malformed")
        try:
            bytes.fromhex(event_hash)
        except ValueError as exc:
            raise EvidenceVerificationError("audit hash is malformed") from exc
        if not isinstance(event_id, str) or not event_id:
            raise EvidenceVerificationError("audit event ID is malformed")
        hash_by_seq[expected_seq] = event_hash
        event_id_by_seq[expected_seq] = event_id
        expected_seq += 1
    scope = manifest.get("scope")
    if not isinstance(scope, dict):
        raise EvidenceVerificationError("manifest scope is invalid")
    through_seq = scope.get("through_seq")
    from_seq = scope.get("from_seq")
    if not isinstance(through_seq, int) or not isinstance(from_seq, int):
        raise EvidenceVerificationError("manifest sequence bounds are invalid")
    if expected_seq - 1 != through_seq:
        raise EvidenceVerificationError("audit hash prefix does not reach through_seq")
    if through_seq == 0:
        if scope.get("snapshot_event_hash") is not None or scope.get("snapshot_at") is not None:
            raise EvidenceVerificationError("empty audit snapshot metadata is invalid")
    elif scope.get("snapshot_event_hash") != hash_by_seq[through_seq]:
        raise EvidenceVerificationError("snapshot event hash does not match through_seq")

    genesis = "0" * 64
    previous_selected_seq = from_seq - 1
    for event in records["audit_events"]:
        seq = event.get("seq")
        if (
            not isinstance(seq, int)
            or not from_seq <= seq <= through_seq
            or seq <= previous_selected_seq
        ):
            raise EvidenceVerificationError("selected audit event order is invalid")
        previous_selected_seq = seq
        if (
            hash_by_seq.get(seq) != event.get("event_hash")
            or event_id_by_seq.get(seq) != event.get("event_id")
        ):
            raise EvidenceVerificationError("selected audit event is absent from hash prefix")
        expected_prev = genesis if seq == 1 else hash_by_seq.get(seq - 1)
        if event.get("prev_hash") != expected_prev:
            raise EvidenceVerificationError("selected audit event link is invalid")
        expected_hash = audit._hash_event(
            event["prev_hash"],
            event["ts_iso"],
            event["actor"],
            event["action"],
            event.get("agent_id"),
            event["detail"],
            seq=seq,
            hash_schema=event["hash_schema"],
        )
        if expected_hash != event["event_hash"]:
            raise EvidenceVerificationError("selected audit event hash is invalid")

    for anchor in records["anchors"]:
        count = anchor["event_count"]
        if count < 1 or count > len(hashes):
            raise EvidenceVerificationError("anchor coverage is outside the hash prefix")
        if event_id_by_seq[count] != anchor["last_event_id"]:
            raise EvidenceVerificationError("anchor last event does not match")
        root = anchor_core.merkle_root([item["event_hash"] for item in hashes[:count]])
        if root != anchor["merkle_root"]:
            raise EvidenceVerificationError("anchor Merkle root does not match")
        for publication in anchor["publications"]:
            receipt = publication.get("receipt")
            digest = publication.get("receipt_sha256")
            if receipt is not None and digest != _sha256(canonical_json(receipt)):
                raise EvidenceVerificationError("anchor receipt digest does not match")


async def build_bundle(
    db: AsyncSession,
    *,
    tenant: Client,
    from_seq: int = 1,
    through_seq: int | None = None,
    record_limit: int = DEFAULT_RECORD_LIMIT,
) -> BundleArtifact:
    """Build one tenant's evidence against a pinned global audit prefix."""
    if not 1 <= record_limit <= MAX_RECORD_LIMIT:
        raise EvidenceBundleError(
            "evidence_record_limit_invalid", state="invalid", status_code=422
        )
    tail = (
        await db.execute(select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(1))
    ).scalar_one_or_none()
    tail_seq = tail.seq if tail is not None and tail.seq is not None else 0
    resolved_through = tail_seq if through_seq is None else through_seq
    if resolved_through < 0 or resolved_through > tail_seq:
        raise EvidenceBundleError(
            "evidence_snapshot_unavailable", state="unavailable", status_code=409
        )
    if resolved_through and from_seq > resolved_through:
        raise EvidenceBundleError(
            "evidence_sequence_range_invalid", state="invalid", status_code=422
        )
    if resolved_through > record_limit:
        # ``audit_hashes`` is a complete prefix by contract. Refuse before
        # loading an artifact larger than the caller-authorized bound.
        raise EvidenceBundleError(
            "evidence_record_limit_exceeded", state="limit_exceeded", status_code=413
        )

    chain_ok, _broken_at = await audit.verify_chain(db, through_seq=resolved_through)
    if not chain_ok:
        raise EvidenceBundleError(
            "audit_chain_not_intact", state="tampered", status_code=409
        )
    prefix_events = list(
        (
            await db.execute(
                select(AuditEvent)
                .where(AuditEvent.seq <= resolved_through)
                .order_by(AuditEvent.seq.asc())
            )
        ).scalars().all()
    ) if resolved_through else []

    sites = list(
        (
            await db.execute(
                select(Site).where(Site.client_id == tenant.id).order_by(Site.id)
            )
        ).scalars().all()
    )
    site_ids = [site.id for site in sites]
    agents = list(
        (
            await db.execute(
                select(Agent)
                .where(Agent.site_id.in_(site_ids))
                .order_by(Agent.id)
            )
        ).scalars().all()
    ) if site_ids else []
    agent_ids = {agent.id for agent in agents}

    selected_events = [
        event
        for event in prefix_events
        if (event.seq or 0) >= from_seq
        and (
            event.organization_id == tenant.id
            or (event.organization_id is None and event.agent_id in agent_ids)
        )
    ]
    selected_event_ids = {event.id for event in selected_events}
    referenced_command_ids = {
        event.detail.get("command_id")
        for event in selected_events
        if isinstance(event.detail, dict) and event.detail.get("command_id")
    }

    command_stmt = select(Command).where(Command.agent_id.in_(agent_ids))
    if selected_event_ids or referenced_command_ids:
        command_stmt = command_stmt.where(
            or_(
                Command.dispatch_audit_event_id.in_(selected_event_ids),
                Command.id.in_(referenced_command_ids),
            )
        )
        commands = list(
            (await db.execute(command_stmt.order_by(Command.id))).scalars().all()
        )
    else:
        commands = []

    dispatch_details = {
        event.detail.get("command_id"): event.detail
        for event in prefix_events
        if event.action == "command.dispatched"
        and isinstance(event.detail, dict)
        and event.detail.get("command_id")
    }

    memberships = list(
        (
            await db.execute(
                select(OperatorClientMembership)
                .where(OperatorClientMembership.client_id == tenant.id)
                .order_by(OperatorClientMembership.operator_id)
            )
        ).scalars().all()
    )
    membership_by_operator = {item.operator_id: item for item in memberships}
    actor_ids = set(membership_by_operator)
    actor_ids.update(
        event.actor_user_id for event in selected_events if event.actor_user_id
    )
    actor_ids.update(
        command.actor_operator_id for command in commands if command.actor_operator_id
    )
    operators = list(
        (
            await db.execute(
                select(Operator).where(Operator.id.in_(actor_ids)).order_by(Operator.email)
            )
        ).scalars().all()
    ) if actor_ids else []
    known_emails = {operator.email for operator in operators}
    historical_actors = sorted(
        {event.actor for event in selected_events if event.actor not in known_emails}
        | {
            command.actor_email
            for command in commands
            if command.actor_email and command.actor_email not in known_emails
        }
    )

    scope_filter = [MonitoringPolicy.scope == MonitoringScope.global_]
    patch_scope_filter = [PatchApprovalPolicy.scope == MonitoringScope.global_]
    scope_filter.append(
        (MonitoringPolicy.scope == MonitoringScope.client)
        & (MonitoringPolicy.scope_id == tenant.id)
    )
    patch_scope_filter.append(
        (PatchApprovalPolicy.scope == MonitoringScope.client)
        & (PatchApprovalPolicy.scope_id == tenant.id)
    )
    if site_ids:
        scope_filter.append(
            (MonitoringPolicy.scope == MonitoringScope.site)
            & MonitoringPolicy.scope_id.in_(site_ids)
        )
        patch_scope_filter.append(
            (PatchApprovalPolicy.scope == MonitoringScope.site)
            & PatchApprovalPolicy.scope_id.in_(site_ids)
        )
    if agent_ids:
        scope_filter.append(
            (MonitoringPolicy.scope == MonitoringScope.agent)
            & MonitoringPolicy.scope_id.in_(agent_ids)
        )
        patch_scope_filter.append(
            (PatchApprovalPolicy.scope == MonitoringScope.agent)
            & PatchApprovalPolicy.scope_id.in_(agent_ids)
        )
    monitoring_policies = list(
        (
            await db.execute(
                select(MonitoringPolicy).where(or_(*scope_filter)).order_by(MonitoringPolicy.id)
            )
        ).scalars().all()
    )
    patch_policies = list(
        (
            await db.execute(
                select(PatchApprovalPolicy)
                .where(or_(*patch_scope_filter))
                .order_by(PatchApprovalPolicy.id)
            )
        ).scalars().all()
    )
    monitoring_ids = [policy.id for policy in monitoring_policies]
    patch_ids = [policy.id for policy in patch_policies]
    monitoring_revisions = list(
        (
            await db.execute(
                select(MonitoringPolicyRevision)
                .where(MonitoringPolicyRevision.policy_id.in_(monitoring_ids))
                .order_by(MonitoringPolicyRevision.policy_id, MonitoringPolicyRevision.version)
            )
        ).scalars().all()
    ) if monitoring_ids else []
    patch_revisions = list(
        (
            await db.execute(
                select(PatchApprovalPolicyRevision)
                .where(PatchApprovalPolicyRevision.policy_id.in_(patch_ids))
                .order_by(
                    PatchApprovalPolicyRevision.policy_id,
                    PatchApprovalPolicyRevision.version,
                )
            )
        ).scalars().all()
    ) if patch_ids else []
    monitoring_by_id = {policy.id: policy for policy in monitoring_policies}
    patch_by_id = {policy.id: policy for policy in patch_policies}

    applicable_anchor = (
        await db.execute(
            select(AuditAnchor)
            .where(AuditAnchor.event_count <= resolved_through)
            .order_by(AuditAnchor.event_count.desc(), AuditAnchor.id.desc())
            .limit(1)
        )
    ).scalar_one_or_none() if resolved_through else None
    publications: list[AnchorPublication] = []
    if applicable_anchor is not None:
        covered = prefix_events[: applicable_anchor.event_count]
        if (
            len(covered) != applicable_anchor.event_count
            or covered[-1].id != applicable_anchor.last_event_id
            or anchor_core.merkle_root([item.event_hash for item in covered])
            != applicable_anchor.merkle_root
        ):
            raise EvidenceBundleError(
                "audit_anchor_not_intact", state="tampered", status_code=409
            )
        publications = list(
            (
                await db.execute(
                    select(AnchorPublication)
                    .where(AnchorPublication.anchor_id == applicable_anchor.id)
                    .order_by(AnchorPublication.backend, AnchorPublication.id)
                )
            ).scalars().all()
        )
        for publication in publications:
            intact, _reason = anchor_publish.verify_receipt(publication)
            if publication.status == "published" and not intact:
                raise EvidenceBundleError(
                    "anchor_receipt_not_intact", state="tampered", status_code=409
                )
            if publication.status != "published" and (
                publication.receipt is not None
                or publication.receipt_sha256 is not None
            ):
                raise EvidenceBundleError(
                    "anchor_receipt_not_intact", state="tampered", status_code=409
                )

    try:
        active_key_id, signing_keys = load_keyring()
        key_records = [
            {
                "key_id": key_id,
                "status": key.status,
                "active": key_id == active_key_id,
                "public_key_pem": key.public_key_pem,
            }
            for key_id, key in sorted(signing_keys.items())
        ]
    except Exception as exc:
        raise EvidenceBundleError(
            "evidence_signing_keys_unavailable", state="unavailable", status_code=503
        ) from exc

    command_key_ids = {command.signing_key_id for command in commands if command.signing_key_id}
    missing_key_ids = sorted(command_key_ids - set(signing_keys))
    legacy_unkeyed = sum(1 for command in commands if not command.signing_key_id)

    policy_records: list[dict[str, Any]] = []
    for revision in monitoring_revisions:
        policy = monitoring_by_id[revision.policy_id]
        policy_records.append(
            {
                "policy_type": "monitoring",
                "policy_id": policy.id,
                "name": _safe_value(policy.name),
                "scope": _enum(policy.scope),
                "scope_id": policy.scope_id,
                "enabled": policy.enabled,
                "policy_created_at": _timestamp(policy.created_at),
                "revision_id": revision.id,
                "revision": revision.version,
                "definition": _safe_value(revision.checks),
                "change_note": _digest_text(revision.change_note),
                "created_by": revision.created_by,
                "created_at": _timestamp(revision.created_at),
            }
        )
    for revision in patch_revisions:
        policy = patch_by_id[revision.policy_id]
        policy_records.append(
            {
                "policy_type": "patch_approval",
                "policy_id": policy.id,
                "name": _safe_value(policy.name),
                "scope": _enum(policy.scope),
                "scope_id": policy.scope_id,
                "enabled": policy.enabled,
                "policy_created_at": _timestamp(policy.created_at),
                "revision_id": revision.id,
                "revision": revision.version,
                "definition": _safe_value(
                    {
                        "rules": revision.rules,
                        "default_action": revision.default_action,
                        "require_maintenance_window": revision.require_maintenance_window,
                        "reboot_policy": revision.reboot_policy,
                        "reboot_delay_seconds": revision.reboot_delay_seconds,
                        "reboot_requires_no_user": revision.reboot_requires_no_user,
                        "max_install_attempts": revision.max_install_attempts,
                    }
                ),
                "change_note": _digest_text(revision.change_note),
                "created_by": revision.created_by,
                "created_at": _timestamp(revision.created_at),
            }
        )
    policy_records.sort(
        key=lambda item: (
            item["policy_type"], item["scope"], item["scope_id"] or "",
            item["policy_id"], item["revision"],
        )
    )

    action_records = []
    result_records = []
    for command in commands:
        detail = dispatch_details.get(command.id, {})
        action_records.append(
            {
                "command_id": command.id,
                "agent_id": command.agent_id,
                "kind": _enum(command.kind),
                "actor_id": command.actor_operator_id,
                "actor": command.actor_email,
                "envelope_version": command.envelope_version,
                "schema_version": command.schema_version,
                "issued_at": _timestamp(command.issued_at),
                "expires_at": _timestamp(command.expires_at),
                "nonce": command.nonce,
                "signing_key_id": command.signing_key_id,
                "signature": command.signature,
                "envelope_sha256": detail.get("envelope_sha256"),
                "payload_keys": detail.get("payload_keys", sorted(command.payload or {})),
                "payload_state": "withheld_sensitive",
                "script_version_id": command.script_version_id,
                "script_parameter_value_set_id": command.script_parameter_value_set_id,
                "dispatch_audit_event_id": command.dispatch_audit_event_id,
            }
        )
        result_records.append(
            {
                "command_id": command.id,
                "status": _enum(command.status),
                "exit_code": command.exit_code,
                "created_at": _timestamp(command.created_at),
                "dispatched_at": _timestamp(command.dispatched_at),
                "agent_completed_at": _timestamp(command.agent_completed_at),
                "completed_at": _timestamp(command.completed_at),
                "planned_at": _timestamp(command.planned_at),
                "attempt": command.attempt,
                "parent_command_id": command.parent_command_id,
                "stdout": {
                    "state": (
                        "withheld_sensitive"
                        if command.stdout is not None
                        else "not_recorded"
                    ),
                    "truncated": command.stdout_truncated,
                    "total_bytes": command.stdout_total_bytes,
                },
                "stderr": {
                    "state": (
                        "withheld_sensitive"
                        if command.stderr is not None
                        else "not_recorded"
                    ),
                    "truncated": command.stderr_truncated,
                    "total_bytes": command.stderr_total_bytes,
                },
            }
        )

    actor_records = [
        {
            "actor_id": operator.id,
            "email": operator.email,
            "global_role": _enum(operator.role),
            "client_role": (
                _enum(membership_by_operator[operator.id].role)
                if operator.id in membership_by_operator
                else None
            ),
            "platform_admin": operator.is_platform_admin,
            "disabled": operator.disabled,
            "membership_created_at": (
                _timestamp(membership_by_operator[operator.id].created_at)
                if operator.id in membership_by_operator
                else None
            ),
            "identity_state": "current",
        }
        for operator in operators
    ]
    actor_records.extend(
        {
            "actor_id": None,
            "email": actor,
            "global_role": None,
            "client_role": None,
            "platform_admin": None,
            "disabled": None,
            "membership_created_at": None,
            "identity_state": "historical_or_system",
        }
        for actor in historical_actors
    )
    actor_records.sort(key=lambda item: (item["email"], item["actor_id"] or ""))

    anchor_records = []
    if applicable_anchor is not None:
        anchor_records.append(
            {
                "anchor_id": applicable_anchor.id,
                "created_at": _timestamp(applicable_anchor.created_at),
                "event_count": applicable_anchor.event_count,
                "last_event_id": applicable_anchor.last_event_id,
                "merkle_root": applicable_anchor.merkle_root,
                "publications": [
                    {
                        "backend": publication.backend,
                        "status": publication.status,
                        "uri": publication.uri,
                        "receipt": publication.receipt,
                        "receipt_sha256": publication.receipt_sha256,
                        "published_at": _timestamp(publication.published_at),
                    }
                    for publication in publications
                ],
            }
        )

    records: dict[str, list[dict[str, Any]]] = {
        "tenant": [
            {
                "tenant_id": tenant.id,
                "name": _safe_value(tenant.name),
                "created_at": _timestamp(tenant.created_at),
            }
        ],
        "actors": actor_records,
        "sites": [
            {
                "site_id": site.id,
                "tenant_id": site.client_id,
                "name": _safe_value(site.name),
                "created_at": _timestamp(site.created_at),
            }
            for site in sites
        ],
        "endpoints": [
            {
                "agent_id": agent.id,
                "site_id": agent.site_id,
                "name": _safe_value(agent.name),
                "hostname": _safe_value(agent.hostname),
                "os": _safe_value(agent.os),
                "os_version": _safe_value(agent.os_version),
                "agent_version": agent.agent_version,
                "architecture": agent.architecture,
                "environment": _safe_value(agent.environment),
                "labels": sorted(_safe_value(agent.labels or [])),
                "owner_operator_id": agent.owner_user_id,
                "status": _enum(agent.status),
                "trust_state": _enum(agent.trust_state),
                "command_envelope_versions": sorted(agent.command_envelope_versions or []),
                "supported_capabilities": sorted(agent.supported_capabilities or []),
                "credential_issued_at": _timestamp(agent.credential_issued_at),
                "credential_expires_at": _timestamp(agent.credential_expires_at),
                "enrolled_at": _timestamp(agent.enrolled_at),
                "last_seen_at": _timestamp(agent.last_seen_at),
                "revoked_at": _timestamp(agent.revoked_at),
            }
            for agent in agents
        ],
        "policies": policy_records,
        "signed_actions": action_records,
        "results": result_records,
        "audit_events": [
            {
                "event_id": event.id,
                "seq": event.seq,
                "hash_schema": event.hash_schema,
                "ts": _timestamp(event.ts),
                "ts_iso": event.ts_iso,
                "actor": event.actor,
                "actor_user_id": event.actor_user_id,
                "action": event.action,
                "agent_id": event.agent_id,
                "enrollment_token_id": event.enrollment_token_id,
                "organization_id": event.organization_id,
                "source_ip": event.source_ip,
                "user_agent": event.user_agent,
                "detail": event.detail,
                "prev_hash": event.prev_hash,
                "event_hash": event.event_hash,
            }
            for event in selected_events
        ],
        "audit_hashes": [
            {"seq": event.seq, "event_id": event.id, "event_hash": event.event_hash}
            for event in prefix_events
        ],
        "anchors": anchor_records,
        "verification_keys": key_records,
    }

    for name, section in records.items():
        _bounded(section, record_limit, name)
    total_records = sum(len(section) for section in records.values())
    if total_records > record_limit:
        raise EvidenceBundleError(
            "evidence_record_limit_exceeded", state="limit_exceeded", status_code=413
        )

    coverage = applicable_anchor.event_count if applicable_anchor is not None else 0
    verification = {
        "audit_chain": {
            "state": "intact",
            "through_seq": resolved_through,
            "selected_event_count": len(selected_events),
        },
        "anchor": {
            "state": "verified" if applicable_anchor is not None else "unavailable",
            "coverage_through_seq": coverage,
            "unanchored_event_count": max(0, resolved_through - coverage),
            "publication_state": (
                "published"
                if any(publication.status == "published" for publication in publications)
                else "pending" if publications else "unavailable"
            ),
        },
        "command_signatures": {
            "state": "incomplete" if missing_key_ids or legacy_unkeyed else "available",
            "missing_key_ids": missing_key_ids,
            "legacy_unkeyed_count": legacy_unkeyed,
            "payload_verification": "metadata_only_payload_withheld",
        },
        "redaction": {
            "audit_details": "stored_sanitized_representation",
            "command_payloads": "withheld_sensitive",
            "command_outputs": "withheld_sensitive",
            "policy_free_text": "digest_only",
        },
    }
    snapshot = prefix_events[-1] if prefix_events else None
    return _build_document(
        tenant_id=tenant.id,
        from_seq=from_seq,
        through_seq=resolved_through,
        snapshot_event_hash=snapshot.event_hash if snapshot else None,
        snapshot_at=snapshot.ts_iso if snapshot else None,
        records=records,
        verification=verification,
    )
