#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Verify a NodeLink evidence bundle without database or application access.

This issue-#79 reference verifier uses only the Python standard library.  It
checks the versioned manifest, section counts/digests, bundle ID, selected audit
event hashes and links, the exported global hash prefix, Merkle anchors, and
external-publication receipt digests.  Issue #82 will package the wider
cross-platform verification CLI; this script is the clean-room contract proof.

Exit 0 means the artifact is internally consistent.  It is not a compliance
opinion and does not prove that an unpublished anchor exists outside NodeLink.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sys
from pathlib import Path
from typing import Any

FORMAT = "nodelink-evidence-bundle"
VERSION = 1
SECTIONS = (
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
GENESIS = "0" * 64


class VerificationError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def serialize_csv(document: dict[str, Any]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream,
        fieldnames=CSV_FIELDS,
        lineterminator="\n",
        quoting=csv.QUOTE_ALL,
    )
    writer.writeheader()
    manifest_json = canonical(document["manifest"])
    writer.writerow(
        {
            "section": "manifest",
            "ordinal": 0,
            "record_sha256": digest(manifest_json),
            "record_json": manifest_json.decode("utf-8"),
        }
    )
    for section in SECTIONS:
        for ordinal, record in enumerate(document["records"][section], 1):
            encoded = canonical(record)
            writer.writerow(
                {
                    "section": section,
                    "ordinal": ordinal,
                    "record_sha256": digest(encoded),
                    "record_json": encoded.decode("utf-8"),
                }
            )
    return stream.getvalue().encode("utf-8")


def event_hash(event: dict[str, Any]) -> str:
    document = {
        "prev_hash": event["prev_hash"],
        "ts": event["ts_iso"],
        "actor": event["actor"],
        "action": event["action"],
        "agent_id": event.get("agent_id"),
        "detail": event["detail"],
    }
    if event["hash_schema"] >= 2:
        document["seq"] = event["seq"]
    return digest(canonical(document))


def merkle_root(hashes: list[str]) -> str:
    if not hashes:
        raise VerificationError("anchor cannot cover an empty hash list")
    try:
        level = [bytes.fromhex(value) for value in hashes]
    except ValueError as exc:
        raise VerificationError("audit hash is not hexadecimal") from exc
    while len(level) > 1:
        next_level = []
        for index in range(0, len(level) - 1, 2):
            next_level.append(
                hashlib.sha256(level[index] + level[index + 1]).digest()
            )
        if len(level) % 2:
            next_level.append(level[-1])
        level = next_level
    return level[0].hex()


def parse_csv(payload: bytes) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError("CSV is not UTF-8") from exc
    reader = csv.DictReader(io.StringIO(text, newline=""))
    if tuple(reader.fieldnames or ()) != CSV_FIELDS:
        raise VerificationError("CSV header does not match version 1")
    records = {section: [] for section in SECTIONS}
    ordinals = {section: 1 for section in SECTIONS}
    manifest = None
    for row in reader:
        try:
            encoded = row["record_json"].encode("utf-8")
            if digest(encoded) != row["record_sha256"]:
                raise VerificationError("CSV row digest mismatch")
            record = json.loads(row["record_json"])
            ordinal = int(row["ordinal"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            if isinstance(exc, VerificationError):
                raise
            raise VerificationError("malformed CSV row") from exc
        if canonical(record) != encoded:
            raise VerificationError("CSV record JSON is not canonical")
        section = row["section"]
        if section == "manifest":
            if manifest is not None or ordinal != 0:
                raise VerificationError("CSV manifest row is invalid")
            manifest = record
        elif section not in records:
            raise VerificationError("CSV contains an unknown section")
        else:
            if ordinal != ordinals[section]:
                raise VerificationError("CSV section ordinals are not contiguous")
            ordinals[section] += 1
            records[section].append(record)
    if manifest is None:
        raise VerificationError("CSV manifest row is missing")
    document = {
        "format": manifest.get("format"),
        "version": manifest.get("version"),
        "manifest": manifest,
        "records": records,
    }
    if serialize_csv(document) != payload:
        raise VerificationError("CSV artifact is not canonically encoded")
    return document


def load_artifact(path: Path) -> dict[str, Any]:
    payload = path.read_bytes()
    if path.suffix.lower() == ".csv":
        return parse_csv(payload)
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError("artifact is not valid JSON or version-1 CSV") from exc
    if not isinstance(value, dict):
        raise VerificationError("JSON artifact must be an object")
    if canonical(value) != payload:
        raise VerificationError("JSON artifact is not canonically encoded")
    return value


def verify(document: dict[str, Any]) -> str:
    if document.get("format") != FORMAT or document.get("version") != VERSION:
        raise VerificationError("unsupported evidence format/version")
    manifest = document.get("manifest")
    records = document.get("records")
    if not isinstance(manifest, dict) or not isinstance(records, dict):
        raise VerificationError("manifest or records are missing")
    if set(records) != set(SECTIONS) or len(records) != len(SECTIONS):
        raise VerificationError("sections are missing or unknown")

    sections = manifest.get("sections")
    if not isinstance(sections, list):
        raise VerificationError("manifest section index is missing")
    if [section.get("name") for section in sections] != list(SECTIONS):
        raise VerificationError("manifest section order is invalid")
    for section in sections:
        name = section["name"]
        if section.get("record_count") != len(records[name]):
            raise VerificationError(f"record count mismatch in {name}")
        if section.get("sha256") != digest(canonical(records[name])):
            raise VerificationError(f"section digest mismatch in {name}")

    bundle_id = manifest.get("bundle_id")
    base_manifest = {key: value for key, value in manifest.items() if key != "bundle_id"}
    if bundle_id != digest(canonical(base_manifest)):
        raise VerificationError("bundle ID does not match manifest")

    hashes = records["audit_hashes"]
    by_seq: dict[int, dict[str, Any]] = {}
    for expected, item in enumerate(hashes, 1):
        if item.get("seq") != expected:
            raise VerificationError("audit hash prefix is not contiguous")
        value = item.get("event_hash")
        if not isinstance(value, str) or len(value) != 64:
            raise VerificationError("audit hash is malformed")
        try:
            bytes.fromhex(value)
        except ValueError as exc:
            raise VerificationError("audit hash is malformed") from exc
        if not isinstance(item.get("event_id"), str) or not item["event_id"]:
            raise VerificationError("audit event ID is malformed")
        by_seq[expected] = item
    scope = manifest.get("scope")
    if not isinstance(scope, dict):
        raise VerificationError("manifest scope is invalid")
    through_seq = scope.get("through_seq")
    from_seq = scope.get("from_seq")
    if not isinstance(through_seq, int) or not isinstance(from_seq, int):
        raise VerificationError("manifest sequence bounds are invalid")
    if through_seq != len(hashes):
        raise VerificationError("audit hash prefix does not reach through_seq")
    if through_seq == 0:
        if scope.get("snapshot_event_hash") is not None or scope.get("snapshot_at") is not None:
            raise VerificationError("empty audit snapshot metadata is invalid")
    elif scope.get("snapshot_event_hash") != by_seq[through_seq]["event_hash"]:
        raise VerificationError("snapshot event hash does not match through_seq")

    previous_selected_seq = from_seq - 1
    for event in records["audit_events"]:
        seq = event.get("seq")
        if (
            not isinstance(seq, int)
            or not from_seq <= seq <= through_seq
            or seq <= previous_selected_seq
        ):
            raise VerificationError("selected event order is invalid")
        previous_selected_seq = seq
        if (
            seq not in by_seq
            or by_seq[seq]["event_hash"] != event.get("event_hash")
            or by_seq[seq]["event_id"] != event.get("event_id")
        ):
            raise VerificationError("selected event is absent from audit prefix")
        previous = GENESIS if seq == 1 else by_seq[seq - 1]["event_hash"]
        if event.get("prev_hash") != previous:
            raise VerificationError("selected event link is invalid")
        if event_hash(event) != event.get("event_hash"):
            raise VerificationError("selected event hash is invalid")

    for anchor in records["anchors"]:
        count = anchor.get("event_count")
        if not isinstance(count, int) or not 1 <= count <= len(hashes):
            raise VerificationError("anchor coverage is invalid")
        if by_seq[count]["event_id"] != anchor.get("last_event_id"):
            raise VerificationError("anchor last event does not match")
        if merkle_root(
            [item["event_hash"] for item in hashes[:count]]
        ) != anchor.get("merkle_root"):
            raise VerificationError("anchor Merkle root does not match")
        for publication in anchor.get("publications", []):
            receipt = publication.get("receipt")
            if receipt is not None and publication.get("receipt_sha256") != digest(
                canonical(receipt)
            ):
                raise VerificationError("publication receipt digest does not match")
    return str(bundle_id)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    args = parser.parse_args()
    try:
        bundle_id = verify(load_artifact(args.artifact))
    except (OSError, VerificationError, KeyError, TypeError, IndexError) as exc:
        print(f"verify-evidence: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"verify-evidence: OK {bundle_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
