#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Verify a NodeLink signed evidence ZIP with an externally trusted public key.

This issue-#80 reference verifier imports no NodeLink application or database
code.  It requires the repository's pinned ``cryptography`` dependency for
Ed25519 and reuses only the sibling clean-room evidence-document verifier.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import re
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import verify_evidence_bundle as bundle_verifier

FORMAT = "nodelink-evidence-package"
VERSION = 1
CONTEXT_NAME = "nodelink-evidence-package:v1"
CONTEXT = (CONTEXT_NAME + ":").encode("ascii")
MANIFEST_PATH = "package-manifest.json"
SIGNATURE_PATH = "signature.json"
EVIDENCE_PATH = "evidence/evidence.json"
REPORT_PATH = "reports/evidence-summary.pdf"
RECEIPTS_PATH = "receipts/anchor-receipts.json"
PUBLIC_KEY_PATH = "keys/evidence-signing-key.pem"
INSTRUCTIONS_PATH = "VERIFY.txt"
CONTENT_PATHS = (
    EVIDENCE_PATH,
    REPORT_PATH,
    RECEIPTS_PATH,
    PUBLIC_KEY_PATH,
    INSTRUCTIONS_PATH,
)
ARCHIVE_PATHS = (MANIFEST_PATH, SIGNATURE_PATH, *CONTENT_PATHS)
MEDIA_TYPES = {
    EVIDENCE_PATH: "application/vnd.nodelink.evidence+json",
    REPORT_PATH: "application/pdf",
    RECEIPTS_PATH: "application/json",
    PUBLIC_KEY_PATH: "application/x-pem-file",
    INSTRUCTIONS_PATH: "text/plain; charset=utf-8",
}
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 48 * 1024 * 1024
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
ZIP_MODE = (stat.S_IFREG | 0o644) << 16
SHA256_RE = re.compile(r"[0-9a-f]{64}")
KEY_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")

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


def valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def safe_path(path: str) -> bool:
    if not path or "\\" in path or "\x00" in path or path.startswith("/"):
        return False
    parsed = PurePosixPath(path)
    return str(parsed) == path and all(
        part not in {"", ".", ".."} for part in parsed.parts
    )


def read_archive(payload: bytes) -> dict[str, bytes]:
    if len(payload) > MAX_ARCHIVE_BYTES:
        raise VerificationError("archive exceeds the size limit")
    try:
        with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
            if archive.comment:
                raise VerificationError("archive comment is not allowed")
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if tuple(names) != ARCHIVE_PATHS or len(names) != len(set(names)):
                raise VerificationError("archive paths or ordering are invalid")
            total = 0
            members: dict[str, bytes] = {}
            for info in infos:
                mode = info.external_attr >> 16
                if not safe_path(info.filename) or info.is_dir() or stat.S_ISLNK(mode):
                    raise VerificationError("unsafe archive member path or type")
                if info.flag_bits & 0x1:
                    raise VerificationError("encrypted archive members are unsupported")
                if info.compress_type != zipfile.ZIP_STORED:
                    raise VerificationError("compressed archive members are unsupported")
                if (
                    info.date_time != ZIP_TIMESTAMP
                    or info.create_system != 3
                    or info.create_version != 20
                    or info.extract_version != 20
                    or info.flag_bits != 0
                    or info.internal_attr != 0
                    or info.external_attr != ZIP_MODE
                    or info.extra
                    or info.comment
                ):
                    raise VerificationError("archive metadata is not canonical")
                if info.file_size > MAX_MEMBER_BYTES or info.compress_size != info.file_size:
                    raise VerificationError("archive member exceeds its bound")
                total += info.file_size
                if total > MAX_ARCHIVE_BYTES:
                    raise VerificationError("archive content exceeds the size limit")
                members[info.filename] = archive.read(info)
            return members
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        raise VerificationError("archive is not a readable ZIP") from exc


def load_object(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict) or canonical(value) != payload:
        raise VerificationError(f"{label} is not canonical JSON")
    return value


def load_key(payload: bytes, label: str) -> tuple[Ed25519PublicKey, bytes]:
    try:
        key = serialization.load_pem_public_key(payload)
    except (TypeError, ValueError) as exc:
        raise VerificationError(f"{label} is not a valid public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise VerificationError(f"{label} is not Ed25519")
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return key, der


def verify_pdf(payload: bytes, bundle_id: str) -> None:
    markers = (
        b"%PDF-1.7",
        b"/StructTreeRoot",
        b"/MarkInfo << /Marked true >>",
        b"/Lang (en-US)",
        b"/DisplayDocTitle true",
        b"/Title (NodeLink Evidence Report)",
        b"/H1",
        b"/H2",
        b"startxref",
        b"%%EOF",
        bundle_id.encode("ascii"),
    )
    if not all(marker in payload for marker in markers):
        raise VerificationError("PDF accessibility or identity markers are incomplete")
    try:
        startxref = int(payload.rsplit(b"startxref\n", 1)[1].splitlines()[0])
    except (IndexError, ValueError) as exc:
        raise VerificationError("PDF cross-reference pointer is malformed") from exc
    if payload[startxref : startxref + 4] != b"xref":
        raise VerificationError("PDF cross-reference pointer is invalid")


def verify(payload: bytes, trusted_public_key: bytes) -> tuple[str, str, str]:
    members = read_archive(payload)
    manifest = load_object(members[MANIFEST_PATH], "package manifest")
    signature = load_object(members[SIGNATURE_PATH], "signature record")
    if (
        manifest.get("format") != FORMAT
        or type(manifest.get("version")) is not int
        or manifest["version"] != VERSION
    ):
        raise VerificationError("unsupported evidence package format")
    if set(manifest) != {
        "format",
        "version",
        "package_id",
        "evidence",
        "files",
        "signing",
    }:
        raise VerificationError("package manifest fields are invalid")
    files = manifest.get("files")
    if (
        not isinstance(files, list)
        or any(not isinstance(item, dict) for item in files)
        or [item.get("path") for item in files] != list(CONTENT_PATHS)
    ):
        raise VerificationError("package file manifest is incomplete or unordered")
    for item in files:
        if not isinstance(item, dict) or set(item) != {
            "path",
            "media_type",
            "size_bytes",
            "sha256",
        }:
            raise VerificationError("package file descriptor is invalid")
        path = item["path"]
        if (
            not isinstance(path, str)
            or type(item.get("size_bytes")) is not int
            or not valid_sha256(item.get("sha256"))
        ):
            raise VerificationError("package file descriptor is invalid")
        content = members[path]
        if item.get("media_type") != MEDIA_TYPES[path]:
            raise VerificationError("package member media type is invalid")
        if item.get("size_bytes") != len(content) or item.get("sha256") != digest(
            content
        ):
            raise VerificationError("package member digest or size mismatch")

    package_id = manifest.get("package_id")
    base_manifest = {key: value for key, value in manifest.items() if key != "package_id"}
    if not valid_sha256(package_id) or package_id != digest(canonical(base_manifest)):
        raise VerificationError("package ID does not match the manifest")
    signing = manifest.get("signing")
    if not isinstance(signing, dict) or set(signing) != {
        "algorithm",
        "context",
        "key_id",
        "public_key_path",
        "public_key_sha256",
        "public_key_fingerprint_sha256",
    }:
        raise VerificationError("package signing metadata is invalid")
    if (
        signing.get("algorithm") != "Ed25519"
        or signing.get("context") != CONTEXT_NAME
        or signing.get("public_key_path") != PUBLIC_KEY_PATH
        or not isinstance(signing.get("key_id"), str)
        or KEY_ID_RE.fullmatch(signing["key_id"]) is None
        or not valid_sha256(signing.get("public_key_sha256"))
        or not valid_sha256(signing.get("public_key_fingerprint_sha256"))
    ):
        raise VerificationError("package signing algorithm or key is unsupported")

    included_pem = members[PUBLIC_KEY_PATH]
    included_key, included_der = load_key(included_pem, "included key")
    _trusted_key, trusted_der = load_key(trusted_public_key, "trusted key")
    if trusted_der != included_der:
        raise VerificationError("included public key is not the trusted key")
    if signing.get("public_key_sha256") != digest(included_pem) or signing.get(
        "public_key_fingerprint_sha256"
    ) != digest(included_der):
        raise VerificationError("included public key does not match the manifest")

    manifest_json = members[MANIFEST_PATH]
    signed_payload = CONTEXT + manifest_json
    if set(signature) != {
        "format",
        "version",
        "package_id",
        "manifest_sha256",
        "signed_payload_sha256",
        "signature",
    }:
        raise VerificationError("signature record fields are invalid")
    if (
        signature.get("format") != FORMAT
        or type(signature.get("version")) is not int
        or signature["version"] != VERSION
        or signature.get("package_id") != package_id
        or not valid_sha256(signature.get("manifest_sha256"))
        or not valid_sha256(signature.get("signed_payload_sha256"))
        or not isinstance(signature.get("signature"), str)
        or signature.get("manifest_sha256") != digest(manifest_json)
        or signature.get("signed_payload_sha256") != digest(signed_payload)
    ):
        raise VerificationError("signature record does not bind the manifest")
    try:
        signature_bytes = base64.b64decode(signature.get("signature", ""), validate=True)
        included_key.verify(signature_bytes, signed_payload)
    except (TypeError, ValueError, InvalidSignature) as exc:
        raise VerificationError("package signature is invalid") from exc

    evidence = load_object(members[EVIDENCE_PATH], "evidence document")
    try:
        bundle_verifier.verify(evidence)
    except bundle_verifier.VerificationError as exc:
        raise VerificationError(f"embedded evidence is invalid: {exc}") from exc
    bundle_id = evidence["manifest"]["bundle_id"]
    scope = evidence["manifest"]["scope"]
    if manifest.get("evidence") != {
        "bundle_id": bundle_id,
        "tenant_id": scope["tenant_id"],
        "from_seq": scope["from_seq"],
        "through_seq": scope["through_seq"],
    }:
        raise VerificationError("package scope does not match embedded evidence")
    receipts = load_object(members[RECEIPTS_PATH], "receipt document")
    if receipts != {
        "format": "nodelink-anchor-receipts",
        "version": 1,
        "bundle_id": bundle_id,
        "anchors": evidence["records"]["anchors"],
    }:
        raise VerificationError("receipt document does not match embedded evidence")
    verify_pdf(members[REPORT_PATH], bundle_id)
    return str(package_id), str(bundle_id), str(signing["key_id"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--trusted-public-key", type=Path, required=True)
    args = parser.parse_args()
    try:
        package_id, bundle_id, key_id = verify(
            args.archive.read_bytes(), args.trusted_public_key.read_bytes()
        )
    except (OSError, VerificationError, KeyError, TypeError, IndexError) as exc:
        print(f"verify-evidence-package: FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        "verify-evidence-package: OK "
        f"package={package_id} bundle={bundle_id} key={key_id} trusted-key=matched"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
