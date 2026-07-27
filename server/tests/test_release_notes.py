# SPDX-License-Identifier: AGPL-3.0-only
"""Release-note manifest and final artifact evidence tests."""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.validate_release_notes import (
    EVIDENCE_FORMAT,
    ReleaseNoteError,
    finalize_release,
    load_manifest,
    validate_manifest,
)

SERVER_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVER_ROOT.parent
VALID_MANIFEST = (
    REPO_ROOT
    / "release-notes"
    / "examples"
    / "v0.0.0-release-notes-rehearsal.json"
)
GOLDEN_NOTES = VALID_MANIFEST.with_suffix(".md")
GOLDEN_EVIDENCE = VALID_MANIFEST.with_suffix(".evidence.json")
TEMPLATE = REPO_ROOT / "release-notes" / "TEMPLATE.json"
VALIDATOR = SERVER_ROOT / "scripts" / "validate_release_notes.py"
RELEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"
TAG = "v0.0.0-release-notes-rehearsal"
SOURCE_SHA = "0123456789abcdef0123456789abcdef01234567"
REPOSITORY = "lcolon231/rmm-agent"
RUN_URL = "https://github.com/lcolon231/rmm-agent/actions/runs/117000001"


def _manifest() -> dict:
    return load_manifest(VALID_MANIFEST)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _create_artifacts(directory: Path, manifest: dict) -> None:
    version = manifest["agent"]["version"]
    names = [
        *manifest["agent"]["artifacts"],
        f"nodelink-{version}.spdx.json",
        manifest["installer"]["filename"],
    ]
    for name in names:
        (directory / name).write_bytes(f"rehearsal artifact: {name}\n".encode())

    checksummed = [
        *manifest["agent"]["artifacts"],
        f"nodelink-{version}.spdx.json",
    ]
    checksum_lines = [
        f"{_digest(directory / name)}  {name}" for name in checksummed
    ]
    (directory / "SHA256SUMS.txt").write_text(
        "\n".join(checksum_lines) + "\n", encoding="utf-8"
    )
    installer = manifest["installer"]["filename"]
    (directory / f"{installer}.sha256").write_text(
        f"{_digest(directory / installer)}  {installer}\n", encoding="utf-8"
    )


def test_rehearsal_manifest_passes_preflight():
    normalized = validate_manifest(_manifest(), TAG)

    assert normalized["release"]["tag"] == TAG
    assert normalized["database"]["alembic_revision"] == "0010"
    assert normalized["protocols"]["command_envelopes"] == ["command-v3"]
    assert normalized["rollback"]["target"]["server"]["commit"].startswith("4607ecb")


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda value: value["release"].update(tag="v9.9.9"),
            "does not match workflow tag",
        ),
        (
            lambda value: value["known_limitations"].__setitem__(0, "TBD"),
            "placeholder",
        ),
        (
            lambda value: value["rollback"]["target"]["server"].update(
                commit="abc123"
            ),
            "full non-placeholder Git commit",
        ),
        (
            lambda value: value["rollback"]["target"]["database"][
                "backup_manifest"
            ].update(url="https://github.com/example/repo/releases/latest/backup.json"),
            "mutable evidence",
        ),
        (
            lambda value: value["security_impact"].pop("operator_actions"),
            "must contain at least",
        ),
        (
            lambda value: value["rollback"]["target"]["installer"].update(
                sha256="0" * 64
            ),
            "non-placeholder SHA-256",
        ),
        (
            lambda value: value["rollback"]["target"]["installer"].update(
                sha256="a" * 64
            ),
            "non-placeholder SHA-256",
        ),
        (
            lambda value: value["evidence"]["backup_verification"].update(
                url="https://example.com/backup-verification.json"
            ),
            "placeholder",
        ),
    ],
)
def test_preflight_rejects_incomplete_or_mutable_records(mutate, message):
    manifest = copy.deepcopy(_manifest())
    mutate(manifest)

    with pytest.raises(ReleaseNoteError, match=message):
        validate_manifest(manifest, TAG)


def test_template_is_intentionally_rejected_by_cli():
    result = subprocess.run(
        [
            sys.executable,
            str(VALIDATOR),
            "--manifest",
            str(TEMPLATE),
            "--tag",
            "v1.2.3",
            "--phase",
            "preflight",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 2
    assert "placeholder" in result.stderr


def test_release_workflow_has_one_guarded_publication_path():
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    assert workflow.count("softprops/action-gh-release@v2") == 1
    assert "release-notes-preflight:" in workflow
    assert "--phase preflight" in workflow
    assert "needs: [build, installer]" in workflow
    assert "--phase finalize" in workflow
    assert "body_path: release-artifacts/RELEASE-NOTES.md" in workflow
    assert "release-evidence-${{ steps.version.outputs.version }}.json" in workflow


def test_finalize_verifies_artifacts_and_renders_complete_evidence(tmp_path: Path):
    manifest = _manifest()
    _create_artifacts(tmp_path, manifest)

    evidence, markdown = finalize_release(
        manifest,
        VALID_MANIFEST,
        tmp_path,
        SOURCE_SHA,
        REPOSITORY,
        RUN_URL,
    )

    assert evidence["format"] == EVIDENCE_FORMAT
    assert evidence["source"]["commit"] == SOURCE_SHA
    assert evidence["server"]["commit"] == SOURCE_SHA
    assert len(evidence["agent"]["artifacts"]) == 3
    assert evidence["installer"]["sha256"] == _digest(
        tmp_path / manifest["installer"]["filename"]
    )
    assert evidence["evidence"]["checksums"]["url"].endswith("/SHA256SUMS.txt")
    assert evidence["evidence"]["sbom"]["url"].endswith(
        "/nodelink-0.0.0-release-notes-rehearsal.spdx.json"
    )
    assert len(evidence["evidence"]["provenance"]) == 4
    assert f"sha256:{evidence['installer']['sha256']}" in markdown
    assert markdown == GOLDEN_NOTES.read_text(encoding="utf-8")
    assert evidence == json.loads(GOLDEN_EVIDENCE.read_text(encoding="utf-8"))
    for heading in (
        "## Immutable release identity",
        "## Supported platforms",
        "## Schema and protocol compatibility",
        "## Known limitations",
        "## Upgrade",
        "## Rollback",
        "## Security impact",
        "## Release evidence",
    ):
        assert heading in markdown
    assert (
        f"/blob/{SOURCE_SHA}/docs/WINDOWS-SUPPORT-MATRIX.md" in markdown
    )
    assert "placeholder" not in markdown.lower()


def test_finalize_rejects_a_checksum_mismatch(tmp_path: Path):
    manifest = _manifest()
    _create_artifacts(tmp_path, manifest)
    (tmp_path / "rmm-agent-linux-amd64").write_bytes(b"tampered")

    with pytest.raises(ReleaseNoteError, match="does not match built artifact"):
        finalize_release(
            manifest,
            VALID_MANIFEST,
            tmp_path,
            SOURCE_SHA,
            REPOSITORY,
            RUN_URL,
        )


def test_finalize_cli_writes_notes_and_evidence(tmp_path: Path):
    manifest = _manifest()
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    _create_artifacts(artifacts, manifest)
    notes = tmp_path / "release-notes.md"
    evidence_path = tmp_path / "release-evidence.json"

    result = subprocess.run(
        [
            sys.executable,
            str(VALIDATOR),
            "--manifest",
            str(VALID_MANIFEST),
            "--tag",
            TAG,
            "--phase",
            "finalize",
            "--artifact-dir",
            str(artifacts),
            "--source-sha",
            SOURCE_SHA,
            "--repository",
            REPOSITORY,
            "--run-url",
            RUN_URL,
            "--output-notes",
            str(notes),
            "--output-evidence",
            str(evidence_path),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert notes.read_text(encoding="utf-8").startswith(
        "# NodeLink release-note gate rehearsal"
    )
    record = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert record["format"] == EVIDENCE_FORMAT
    assert record["source"]["workflow_run"] == RUN_URL
