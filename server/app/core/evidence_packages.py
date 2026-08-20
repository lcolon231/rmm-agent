# SPDX-License-Identifier: AGPL-3.0-only
"""Accessible PDF and deterministic signed-ZIP evidence packaging (issue #80).

The package is a presentation and transport layer over the immutable logical
document from :mod:`app.core.evidence_bundles`.  It never queries additional
tenant data.  A fixed-path archive carries the canonical JSON evidence, a
tagged human-readable PDF, anchor receipts, a verification key, and operator
instructions.  A domain-separated Ed25519 signature covers a canonical package
manifest that binds every content member by path, media type, size, and digest.

The public key inside an archive is useful for integrity checks but is not a
trust anchor.  Independent verification compares it to a deployment key
obtained through a separate trusted channel.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import stat
import textwrap
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.core import evidence_bundles
from app.core.keyring import active_signing_key

PACKAGE_FORMAT = "nodelink-evidence-package"
PACKAGE_VERSION = 1
PDF_MEDIA_TYPE = "application/pdf"
ZIP_MEDIA_TYPE = "application/zip"
SIGNING_CONTEXT_NAME = "nodelink-evidence-package:v1"
SIGNING_CONTEXT = (SIGNING_CONTEXT_NAME + ":").encode("ascii")

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

MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 48 * 1024 * 1024
MAX_PDF_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = len(ARCHIVE_PATHS)
_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_ZIP_MODE = (stat.S_IFREG | 0o644) << 16
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_KEY_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
_MEDIA_TYPES = {
    EVIDENCE_PATH: evidence_bundles.JSON_MEDIA_TYPE,
    REPORT_PATH: PDF_MEDIA_TYPE,
    RECEIPTS_PATH: "application/json",
    PUBLIC_KEY_PATH: "application/x-pem-file",
    INSTRUCTIONS_PATH: "text/plain; charset=utf-8",
}

_VERIFY_TEXT = b"""NodeLink deterministic evidence package v1

This archive is not a compliance certification. Verify it with a public key
obtained from the NodeLink operator through a separate trusted channel:

  python server/scripts/verify_evidence_package.py PACKAGE.zip --trusted-public-key PUBLIC.pem

Successful verification proves that the trusted key signed the package
manifest and that the manifest binds every packaged file. It also verifies the
embedded evidence hashes, audit links, Merkle anchor, and receipt digests. It
does not independently prove that an external WORM destination still retains a
receipt; inspect the referenced destination under its own access controls.
"""


class EvidencePackageError(RuntimeError):
    """Stable API failure while rendering or signing a package."""

    def __init__(self, code: str, *, state: str, status_code: int):
        super().__init__(code)
        self.code = code
        self.state = state
        self.status_code = status_code


class PackageVerificationError(ValueError):
    """An evidence PDF or signed archive is malformed or inconsistent."""


@dataclass(frozen=True)
class PackageArtifact:
    content: bytes
    package_id: str
    signing_key_id: str
    manifest: dict[str, Any]


@dataclass(frozen=True)
class PackageVerification:
    package_id: str
    bundle_id: str
    signing_key_id: str
    trusted_key_matched: bool


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _ascii_display(value: Any) -> str:
    text = str(value)
    normalized = unicodedata.normalize("NFKD", text)
    return normalized.encode("ascii", "replace").decode("ascii")


def _pdf_literal(value: str) -> str:
    return (
        _ascii_display(value)
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def _pdf_actual_text(value: str) -> str:
    return (b"\xfe\xff" + value.encode("utf-16-be")).hex().upper()


class _PdfObjects:
    def __init__(self) -> None:
        self._objects: list[bytes | None] = [b""]

    def reserve(self) -> int:
        self._objects.append(None)
        return len(self._objects) - 1

    def add(self, value: bytes) -> int:
        number = self.reserve()
        self.set(number, value)
        return number

    def set(self, number: int, value: bytes) -> None:
        self._objects[number] = value

    def build(self, *, root: int, info: int, identity: str) -> bytes:
        if any(value is None for value in self._objects[1:]):
            raise ValueError("PDF object graph is incomplete")
        output = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for number, value in enumerate(self._objects[1:], 1):
            assert value is not None
            offsets.append(len(output))
            output.extend(f"{number} 0 obj\n".encode("ascii"))
            output.extend(value)
            output.extend(b"\nendobj\n")
        xref = len(output)
        output.extend(f"xref\n0 {len(self._objects)}\n".encode("ascii"))
        output.extend(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
        document_id = hashlib.sha256(identity.encode("ascii")).digest()[:16].hex()
        output.extend(
            (
                f"trailer\n<< /Size {len(self._objects)} /Root {root} 0 R "
                f"/Info {info} 0 R /ID [<{document_id}><{document_id}>] >>\n"
                f"startxref\n{xref}\n%%EOF\n"
            ).encode("ascii")
        )
        return bytes(output)


def _pdf_stream(payload: bytes) -> bytes:
    return (
        f"<< /Length {len(payload)} >>\nstream\n".encode("ascii")
        + payload
        + b"\nendstream"
    )


def _report_elements(artifact: evidence_bundles.BundleArtifact) -> list[tuple[str, str]]:
    document = artifact.document
    manifest = document["manifest"]
    scope = manifest["scope"]
    verification = manifest["verification"]
    tenant = document["records"]["tenant"][0]
    sections = manifest["sections"]

    elements: list[tuple[str, str]] = [
        ("H1", "NodeLink Evidence Report"),
        (
            "P",
            "Compliance-supporting evidence summary; not a certification or a claim "
            "of regulatory completeness.",
        ),
        ("H2", "Scope"),
        ("P", f"Tenant: {tenant['name']} ({tenant['tenant_id']})"),
        ("P", f"Evidence bundle ID: {artifact.bundle_id}"),
        (
            "P",
            f"Audit sequence: {scope['from_seq']} through {scope['through_seq']}",
        ),
        ("P", f"Snapshot event time: {scope['snapshot_at'] or 'no audit events'}"),
        ("H2", "Verification state"),
        ("P", f"Audit chain: {verification['audit_chain']['state']}"),
        (
            "P",
            "External anchor: "
            f"{verification['anchor']['state']}; publications: "
            f"{verification['anchor']['publication_state']}",
        ),
        (
            "P",
            f"Command verification metadata: {verification['command_signatures']['state']}",
        ),
        ("H2", "Evidence inventory"),
    ]
    elements.extend(
        ("P", f"{section['name']}: {section['record_count']} records")
        for section in sections
    )
    elements.extend(
        [
            ("H2", "Sensitive-data handling"),
            (
                "P",
                "Command payload values and stdout/stderr content are withheld. "
                "Policy free text is digest-only; audit details use their stored "
                "centrally sanitized representation.",
            ),
            ("H2", "Independent verification"),
            (
                "P",
                "Use the signed ZIP package and a separately trusted NodeLink public "
                "key to verify the package manifest, evidence hashes, audit links, "
                "Merkle anchor, and receipt digests.",
            ),
        ]
    )
    return elements


def _layout_report(
    elements: list[tuple[str, str]],
) -> list[list[tuple[str, str, int, int]]]:
    pages: list[list[tuple[str, str, int, int]]] = [[]]
    y = 742
    settings = {
        "H1": (18, 28, 72),
        "H2": (13, 22, 76),
        "P": (10, 15, 88),
    }
    for tag, text in elements:
        size, leading, width = settings[tag]
        lines = textwrap.wrap(
            text,
            width=width,
            replace_whitespace=True,
            drop_whitespace=True,
            break_long_words=True,
            break_on_hyphens=False,
        ) or [""]
        for line_index, line in enumerate(lines):
            line_tag = tag if line_index == 0 else "P"
            line_size = size if line_index == 0 else 10
            line_leading = leading if line_index == 0 else 15
            if y - line_leading < 66:
                pages.append([])
                y = 742
            pages[-1].append((line_tag, line, line_size, y))
            y -= line_leading
    return pages


def render_pdf(artifact: evidence_bundles.BundleArtifact) -> bytes:
    """Render a deterministic tagged, screen-reader-oriented PDF summary."""
    pages_layout = _layout_report(_report_elements(artifact))
    objects = _PdfObjects()
    catalog_ref = objects.reserve()
    pages_ref = objects.reserve()
    structure_ref = objects.reserve()
    font_ref = objects.add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    bold_font_ref = objects.add(
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"
    )
    info_ref = objects.add(
        b"<< /Title (NodeLink Evidence Report) /Author (NodeLink) "
        b"/Subject (Deterministic tenant evidence summary) "
        b"/Creator (NodeLink evidence package v1) >>"
    )

    page_refs: list[int] = []
    all_structure_refs: list[int] = []
    parent_tree_entries: list[str] = []
    for page_index, lines in enumerate(pages_layout):
        commands: list[str] = []
        page_ref = objects.reserve()
        structure_refs: list[int] = []
        for mcid, (tag, text, size, y) in enumerate(lines):
            font_name = "F2" if tag in {"H1", "H2"} else "F1"
            commands.extend(
                [
                    f"/{tag} <</MCID {mcid} /ActualText <{_pdf_actual_text(text)}>>> BDC",
                    "BT",
                    f"/{font_name} {size} Tf",
                    f"1 0 0 1 72 {y} Tm",
                    f"({_pdf_literal(text)}) Tj",
                    "ET",
                    "EMC",
                ]
            )
            structure_element = objects.add(
                (
                    f"<< /Type /StructElem /S /{tag} /P {structure_ref} 0 R "
                    f"/Pg {page_ref} 0 R /K {mcid} >>"
                ).encode("ascii")
            )
            structure_refs.append(structure_element)
            all_structure_refs.append(structure_element)
        commands.extend(
            [
                "/Artifact BMC",
                "BT /F1 9 Tf",
                f"1 0 0 1 270 35 Tm (Page {page_index + 1} of {len(pages_layout)}) Tj",
                "ET",
                "EMC",
            ]
        )
        content_ref = objects.add(_pdf_stream("\n".join(commands).encode("ascii")))
        objects.set(
            page_ref,
            (
                f"<< /Type /Page /Parent {pages_ref} 0 R "
                "/MediaBox [0 0 612 792] /Tabs /S "
                f"/StructParents {page_index} "
                f"/Resources << /Font << /F1 {font_ref} 0 R /F2 {bold_font_ref} 0 R >> >> "
                f"/Contents {content_ref} 0 R >>"
            ).encode("ascii"),
        )
        page_refs.append(page_ref)
        refs = " ".join(f"{ref} 0 R" for ref in structure_refs)
        parent_tree_entries.append(f"{page_index} [{refs}]")

    parent_tree_ref = objects.add(
        f"<< /Nums [{' '.join(parent_tree_entries)}] >>".encode("ascii")
    )
    objects.set(
        structure_ref,
        (
            "<< /Type /StructTreeRoot /K ["
            + " ".join(f"{ref} 0 R" for ref in all_structure_refs)
            + f"] /ParentTree {parent_tree_ref} 0 R "
            + f"/ParentTreeNextKey {len(page_refs)} >>"
        ).encode("ascii"),
    )
    objects.set(
        pages_ref,
        (
            f"<< /Type /Pages /Count {len(page_refs)} "
            f"/Kids [{' '.join(f'{ref} 0 R' for ref in page_refs)}] >>"
        ).encode("ascii"),
    )
    objects.set(
        catalog_ref,
        (
            f"<< /Type /Catalog /Pages {pages_ref} 0 R /Lang (en-US) "
            "/ViewerPreferences << /DisplayDocTitle true >> "
            "/MarkInfo << /Marked true >> "
            f"/StructTreeRoot {structure_ref} 0 R >>"
        ).encode("ascii"),
    )
    return objects.build(root=catalog_ref, info=info_ref, identity=artifact.bundle_id)


def verify_pdf(payload: bytes, *, expected_bundle_id: str | None = None) -> None:
    """Check the deterministic PDF's required accessibility and identity markers."""
    required = (
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
    )
    if not all(marker in payload for marker in required):
        raise PackageVerificationError("PDF accessibility structure is incomplete")
    if expected_bundle_id is not None and expected_bundle_id.encode("ascii") not in payload:
        raise PackageVerificationError("PDF does not identify the evidence bundle")
    try:
        startxref = int(payload.rsplit(b"startxref\n", 1)[1].splitlines()[0])
    except (IndexError, ValueError) as exc:
        raise PackageVerificationError("PDF cross-reference pointer is malformed") from exc
    if payload[startxref : startxref + 4] != b"xref":
        raise PackageVerificationError("PDF cross-reference pointer is invalid")


def build_pdf(artifact: evidence_bundles.BundleArtifact) -> bytes:
    """Render and self-verify a bounded PDF before any response can use it."""
    try:
        payload = render_pdf(artifact)
        if len(payload) > MAX_PDF_BYTES:
            raise PackageVerificationError("PDF exceeds the size limit")
        verify_pdf(payload, expected_bundle_id=artifact.bundle_id)
        return payload
    except Exception as exc:
        raise EvidencePackageError(
            "evidence_pdf_render_failed",
            state="invalid",
            status_code=500,
        ) from exc


def _normalized_public_key(key_pem: str) -> tuple[bytes, Ed25519PublicKey, bytes]:
    encoded = (key_pem.replace("\r\n", "\n").strip() + "\n").encode("ascii")
    loaded = serialization.load_pem_public_key(encoded)
    if not isinstance(loaded, Ed25519PublicKey):
        raise ValueError("evidence signing key must be Ed25519")
    der = loaded.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return encoded, loaded, der


def _file_descriptor(path: str, payload: bytes) -> dict[str, Any]:
    return {
        "path": path,
        "media_type": _MEDIA_TYPES[path],
        "size_bytes": len(payload),
        "sha256": _sha256(payload),
    }


def _zip_info(path: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, date_time=_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.create_version = 20
    info.extract_version = 20
    info.flag_bits = 0
    info.internal_attr = 0
    info.external_attr = _ZIP_MODE
    info.extra = b""
    info.comment = b""
    return info


def serialize_archive(entries: list[tuple[str, bytes]]) -> bytes:
    """Serialize fixed, already-validated members with canonical ZIP metadata."""
    stream = io.BytesIO()
    with zipfile.ZipFile(
        stream,
        "w",
        compression=zipfile.ZIP_STORED,
        allowZip64=False,
        strict_timestamps=True,
    ) as archive:
        archive.comment = b""
        for path, payload in entries:
            archive.writestr(_zip_info(path), payload)
    return stream.getvalue()


def build_signed_package(
    artifact: evidence_bundles.BundleArtifact,
    *,
    max_archive_bytes: int = MAX_ARCHIVE_BYTES,
) -> PackageArtifact:
    """Build a deterministic ZIP whose content manifest is Ed25519-signed."""
    try:
        key = active_signing_key()
        public_pem, _public_key, public_der = _normalized_public_key(
            key.public_key_pem
        )
        private_key = key.private_key
        private_public_der = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if private_public_der != public_der:
            raise ValueError("active evidence signing keypair does not match")
    except Exception as exc:
        raise EvidencePackageError(
            "evidence_package_signing_unavailable",
            state="unavailable",
            status_code=503,
        ) from exc

    evidence_json = evidence_bundles.serialize_json(artifact)
    report_pdf = build_pdf(artifact)
    receipts_json = evidence_bundles.canonical_json(
        {
            "format": "nodelink-anchor-receipts",
            "version": 1,
            "bundle_id": artifact.bundle_id,
            "anchors": artifact.document["records"]["anchors"],
        }
    )
    content = {
        EVIDENCE_PATH: evidence_json,
        REPORT_PATH: report_pdf,
        RECEIPTS_PATH: receipts_json,
        PUBLIC_KEY_PATH: public_pem,
        INSTRUCTIONS_PATH: _VERIFY_TEXT,
    }
    files = [_file_descriptor(path, content[path]) for path in CONTENT_PATHS]
    base_manifest = {
        "format": PACKAGE_FORMAT,
        "version": PACKAGE_VERSION,
        "evidence": {
            "bundle_id": artifact.bundle_id,
            "tenant_id": artifact.document["manifest"]["scope"]["tenant_id"],
            "from_seq": artifact.document["manifest"]["scope"]["from_seq"],
            "through_seq": artifact.through_seq,
        },
        "files": files,
        "signing": {
            "algorithm": "Ed25519",
            "context": SIGNING_CONTEXT_NAME,
            "key_id": key.key_id,
            "public_key_path": PUBLIC_KEY_PATH,
            "public_key_sha256": _sha256(public_pem),
            "public_key_fingerprint_sha256": _sha256(public_der),
        },
    }
    package_id = _sha256(evidence_bundles.canonical_json(base_manifest))
    manifest = {**base_manifest, "package_id": package_id}
    manifest_json = evidence_bundles.canonical_json(manifest)
    signed_payload = SIGNING_CONTEXT + manifest_json
    signature_json = evidence_bundles.canonical_json(
        {
            "format": PACKAGE_FORMAT,
            "version": PACKAGE_VERSION,
            "package_id": package_id,
            "manifest_sha256": _sha256(manifest_json),
            "signed_payload_sha256": _sha256(signed_payload),
            "signature": base64.b64encode(private_key.sign(signed_payload)).decode(
                "ascii"
            ),
        }
    )
    entries = [
        (MANIFEST_PATH, manifest_json),
        (SIGNATURE_PATH, signature_json),
        *((path, content[path]) for path in CONTENT_PATHS),
    ]
    for _path, payload in entries:
        if len(payload) > MAX_MEMBER_BYTES:
            raise EvidencePackageError(
                "evidence_package_size_exceeded",
                state="limit_exceeded",
                status_code=413,
            )
    archive = serialize_archive(entries)
    if len(archive) > max_archive_bytes:
        raise EvidencePackageError(
            "evidence_package_size_exceeded",
            state="limit_exceeded",
            status_code=413,
        )
    try:
        verify_signed_package(archive, trusted_public_key_pem=public_pem)
    except PackageVerificationError as exc:
        raise EvidencePackageError(
            "evidence_package_verification_failed",
            state="invalid",
            status_code=500,
        ) from exc
    return PackageArtifact(
        content=archive,
        package_id=package_id,
        signing_key_id=key.key_id,
        manifest=manifest,
    )


def _safe_archive_path(path: str) -> bool:
    if not path or "\\" in path or "\x00" in path or path.startswith("/"):
        return False
    parsed = PurePosixPath(path)
    return str(parsed) == path and all(part not in {"", ".", ".."} for part in parsed.parts)


def read_archive(
    payload: bytes,
    *,
    max_archive_bytes: int = MAX_ARCHIVE_BYTES,
) -> dict[str, bytes]:
    """Read only the canonical bounded archive shape; never extract to disk."""
    if len(payload) > max_archive_bytes:
        raise PackageVerificationError("archive exceeds the size limit")
    try:
        with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
            if archive.comment:
                raise PackageVerificationError("archive comment is not allowed")
            infos = archive.infolist()
            if len(infos) != MAX_ARCHIVE_MEMBERS:
                raise PackageVerificationError("archive member count is invalid")
            names = [info.filename for info in infos]
            if tuple(names) != ARCHIVE_PATHS or len(names) != len(set(names)):
                raise PackageVerificationError("archive paths or ordering are invalid")
            total = 0
            output: dict[str, bytes] = {}
            for info in infos:
                mode = info.external_attr >> 16
                if (
                    not _safe_archive_path(info.filename)
                    or info.is_dir()
                    or stat.S_ISLNK(mode)
                ):
                    raise PackageVerificationError("unsafe archive member path or type")
                if info.flag_bits & 0x1:
                    raise PackageVerificationError("encrypted archive members are unsupported")
                if info.compress_type != zipfile.ZIP_STORED:
                    raise PackageVerificationError("compressed archive members are unsupported")
                if (
                    info.date_time != _ZIP_TIMESTAMP
                    or info.create_system != 3
                    or info.create_version != 20
                    or info.extract_version != 20
                    or info.flag_bits != 0
                    or info.internal_attr != 0
                    or info.external_attr != _ZIP_MODE
                    or info.extra
                    or info.comment
                ):
                    raise PackageVerificationError("archive metadata is not canonical")
                if info.file_size > MAX_MEMBER_BYTES or info.compress_size != info.file_size:
                    raise PackageVerificationError("archive member exceeds its bound")
                total += info.file_size
                if total > max_archive_bytes:
                    raise PackageVerificationError("archive content exceeds the size limit")
                output[info.filename] = archive.read(info)
            return output
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        raise PackageVerificationError("archive is not a readable ZIP") from exc


def _load_canonical_object(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PackageVerificationError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict) or evidence_bundles.canonical_json(value) != payload:
        raise PackageVerificationError(f"{label} is not canonical JSON")
    return value


def _load_ed25519_public_key(payload: bytes, label: str) -> tuple[Ed25519PublicKey, bytes]:
    try:
        key = serialization.load_pem_public_key(payload)
    except (TypeError, ValueError) as exc:
        raise PackageVerificationError(f"{label} is not a valid public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise PackageVerificationError(f"{label} is not Ed25519")
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return key, der


def verify_signed_package(
    payload: bytes,
    *,
    trusted_public_key_pem: bytes | None = None,
) -> PackageVerification:
    """Verify archive shape, manifest, signature, trust pin, evidence, and PDF."""
    members = read_archive(payload)
    manifest = _load_canonical_object(members[MANIFEST_PATH], "package manifest")
    signature = _load_canonical_object(members[SIGNATURE_PATH], "signature record")
    if (
        manifest.get("format") != PACKAGE_FORMAT
        or type(manifest.get("version")) is not int
        or manifest["version"] != PACKAGE_VERSION
    ):
        raise PackageVerificationError("unsupported evidence package format")
    if set(manifest) != {"format", "version", "package_id", "evidence", "files", "signing"}:
        raise PackageVerificationError("package manifest fields are invalid")
    files = manifest.get("files")
    if (
        not isinstance(files, list)
        or any(not isinstance(item, dict) for item in files)
        or [item.get("path") for item in files] != list(CONTENT_PATHS)
    ):
        raise PackageVerificationError("package file manifest is incomplete or unordered")
    for item in files:
        if not isinstance(item, dict) or set(item) != {
            "path",
            "media_type",
            "size_bytes",
            "sha256",
        }:
            raise PackageVerificationError("package file descriptor is invalid")
        path = item["path"]
        if (
            not isinstance(path, str)
            or type(item.get("size_bytes")) is not int
            or not _valid_sha256(item.get("sha256"))
        ):
            raise PackageVerificationError("package file descriptor is invalid")
        content = members[path]
        if item.get("media_type") != _MEDIA_TYPES[path]:
            raise PackageVerificationError("package member media type is invalid")
        if item.get("size_bytes") != len(content) or item.get("sha256") != _sha256(content):
            raise PackageVerificationError("package member digest or size mismatch")

    package_id = manifest.get("package_id")
    base_manifest = {key: value for key, value in manifest.items() if key != "package_id"}
    if not _valid_sha256(package_id) or package_id != _sha256(
        evidence_bundles.canonical_json(base_manifest)
    ):
        raise PackageVerificationError("package ID does not match the manifest")
    signing = manifest.get("signing")
    if not isinstance(signing, dict) or set(signing) != {
        "algorithm",
        "context",
        "key_id",
        "public_key_path",
        "public_key_sha256",
        "public_key_fingerprint_sha256",
    }:
        raise PackageVerificationError("package signing metadata is invalid")
    if (
        signing.get("algorithm") != "Ed25519"
        or signing.get("context") != SIGNING_CONTEXT_NAME
        or signing.get("public_key_path") != PUBLIC_KEY_PATH
        or not isinstance(signing.get("key_id"), str)
        or _KEY_ID_RE.fullmatch(signing["key_id"]) is None
        or not _valid_sha256(signing.get("public_key_sha256"))
        or not _valid_sha256(signing.get("public_key_fingerprint_sha256"))
    ):
        raise PackageVerificationError("package signing algorithm or key is unsupported")

    included_pem = members[PUBLIC_KEY_PATH]
    included_key, included_der = _load_ed25519_public_key(included_pem, "included key")
    if signing.get("public_key_sha256") != _sha256(included_pem) or signing.get(
        "public_key_fingerprint_sha256"
    ) != _sha256(included_der):
        raise PackageVerificationError("included public key does not match the manifest")
    trusted_match = False
    if trusted_public_key_pem is not None:
        _trusted_key, trusted_der = _load_ed25519_public_key(
            trusted_public_key_pem, "trusted key"
        )
        if trusted_der != included_der:
            raise PackageVerificationError("included public key is not the trusted key")
        trusted_match = True

    manifest_json = members[MANIFEST_PATH]
    signed_payload = SIGNING_CONTEXT + manifest_json
    if set(signature) != {
        "format",
        "version",
        "package_id",
        "manifest_sha256",
        "signed_payload_sha256",
        "signature",
    }:
        raise PackageVerificationError("signature record fields are invalid")
    if (
        signature.get("format") != PACKAGE_FORMAT
        or type(signature.get("version")) is not int
        or signature["version"] != PACKAGE_VERSION
        or signature.get("package_id") != package_id
        or not _valid_sha256(signature.get("manifest_sha256"))
        or not _valid_sha256(signature.get("signed_payload_sha256"))
        or not isinstance(signature.get("signature"), str)
        or signature.get("manifest_sha256") != _sha256(manifest_json)
        or signature.get("signed_payload_sha256") != _sha256(signed_payload)
    ):
        raise PackageVerificationError("signature record does not bind the manifest")
    try:
        signature_bytes = base64.b64decode(signature.get("signature", ""), validate=True)
        included_key.verify(signature_bytes, signed_payload)
    except (TypeError, ValueError, InvalidSignature) as exc:
        raise PackageVerificationError("package signature is invalid") from exc

    evidence = _load_canonical_object(members[EVIDENCE_PATH], "evidence document")
    try:
        evidence_bundles.verify_bundle_document(evidence)
    except (
        evidence_bundles.EvidenceVerificationError,
        KeyError,
        TypeError,
        IndexError,
    ) as exc:
        raise PackageVerificationError(f"embedded evidence is invalid: {exc}") from exc
    evidence_scope = manifest.get("evidence")
    if not isinstance(evidence_scope, dict) or evidence_scope != {
        "bundle_id": evidence["manifest"]["bundle_id"],
        "tenant_id": evidence["manifest"]["scope"]["tenant_id"],
        "from_seq": evidence["manifest"]["scope"]["from_seq"],
        "through_seq": evidence["manifest"]["scope"]["through_seq"],
    }:
        raise PackageVerificationError("package scope does not match embedded evidence")
    receipts = _load_canonical_object(members[RECEIPTS_PATH], "receipt document")
    if receipts != {
        "format": "nodelink-anchor-receipts",
        "version": 1,
        "bundle_id": evidence["manifest"]["bundle_id"],
        "anchors": evidence["records"]["anchors"],
    }:
        raise PackageVerificationError("receipt document does not match embedded evidence")
    verify_pdf(
        members[REPORT_PATH],
        expected_bundle_id=evidence["manifest"]["bundle_id"],
    )
    return PackageVerification(
        package_id=package_id,
        bundle_id=evidence["manifest"]["bundle_id"],
        signing_key_id=signing["key_id"],
        trusted_key_matched=trusted_match,
    )
