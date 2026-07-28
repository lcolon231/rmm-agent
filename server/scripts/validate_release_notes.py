# SPDX-License-Identifier: AGPL-3.0-only
"""Validate and render release-specific NodeLink release evidence.

The source manifest is intentionally split from the finalized evidence. A Git
commit cannot contain its own hash, and release artifact digests do not exist
until the workflow builds them. Preflight validates every operator-authored
field before builds start; finalization binds the tag to GITHUB_SHA, verifies
the built checksums, computes every artifact digest, and renders the exact
GitHub Release body plus a machine-readable evidence record.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

FORMAT = "nodelink-release-note-source-v1"
EVIDENCE_FORMAT = "nodelink-release-evidence-v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
TAG_RE = re.compile(r"^v[0-9][0-9A-Za-z.+-]*$")
VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.+-]*$")
ALEMBIC_RE = re.compile(r"^[0-9a-f]{4,64}$")
PROTOCOL_RE = re.compile(r"^[a-z][a-z0-9-]*-v[0-9]+$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
PLACEHOLDER_RE = re.compile(
    r"(?i)(<[^>]+>|example\.(?:com|invalid)|"
    r"\b(?:todo|tbd|changeme|change-me|placeholder|replace-me)\b)"
)
MUTABLE_IDENTIFIER_RE = re.compile(r"(?i)^(?:latest|main|master|develop|head)$")
MUTABLE_URL_RE = re.compile(
    r"(?i)(/blob/(?:main|master)(?:/|$)|/tree/|/releases/latest|"
    r"refs/heads/|[?&](?:ref|version)=(?:main|master|latest)(?:&|$))"
)


class ReleaseNoteError(ValueError):
    """Raised when release evidence is incomplete or inconsistent."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_manifest_sha256(path: Path) -> str:
    """Hash the committed JSON representation consistently on every OS.

    GitHub serves the LF-normalized blob. Windows checkouts may contain CRLF,
    so hashing checkout bytes would bind otherwise identical release evidence
    to the runner platform. JSON cannot contain raw newlines inside strings;
    universal-newline decoding is therefore unambiguous here.
    """
    canonical = path.read_text(encoding="utf-8").encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseNoteError(f"{field} must be an object")
    return value


def _string(value: Any, field: str, *, min_length: int = 1) -> str:
    if not isinstance(value, str):
        raise ReleaseNoteError(f"{field} must be a non-empty string")
    result = value.strip()
    if PLACEHOLDER_RE.search(result):
        raise ReleaseNoteError(f"{field} contains placeholder text")
    if len(result) < min_length:
        raise ReleaseNoteError(f"{field} must be a non-empty string")
    return result


def _strings(
    value: Any, field: str, *, min_items: int = 1, min_length: int = 8
) -> list[str]:
    if not isinstance(value, list) or len(value) < min_items:
        raise ReleaseNoteError(f"{field} must contain at least {min_items} item(s)")
    return [
        _string(item, f"{field}[{index}]", min_length=min_length)
        for index, item in enumerate(value)
    ]


def _sha(value: Any, field: str) -> str:
    result = _string(value, field).lower()
    if not SHA256_RE.fullmatch(result) or len(set(result)) == 1:
        raise ReleaseNoteError(
            f"{field} must be a non-placeholder SHA-256 digest"
        )
    return result


def _commit(value: Any, field: str) -> str:
    result = _string(value, field).lower()
    if not COMMIT_RE.fullmatch(result) or len(set(result)) == 1:
        raise ReleaseNoteError(
            f"{field} must be a full non-placeholder Git commit"
        )
    return result


def _immutable_identifier(value: Any, field: str) -> str:
    result = _string(value, field)
    if MUTABLE_IDENTIFIER_RE.fullmatch(result):
        raise ReleaseNoteError(f"{field} is mutable")
    return result


def _immutable_url(value: Any, field: str) -> str:
    result = _string(value, field)
    if not result.startswith(("https://", "s3://")):
        raise ReleaseNoteError(f"{field} must use https:// or s3://")
    if MUTABLE_URL_RE.search(result):
        raise ReleaseNoteError(f"{field} points to mutable evidence")
    return result


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseNoteError(f"cannot read manifest {path}: {exc}") from exc
    return _mapping(data, "manifest")


def validate_manifest(manifest: dict[str, Any], expected_tag: str) -> dict[str, Any]:
    """Validate and normalize every operator-authored release field."""
    if manifest.get("format") != FORMAT:
        raise ReleaseNoteError(f"format must be {FORMAT!r}")
    if not TAG_RE.fullmatch(expected_tag):
        raise ReleaseNoteError("expected tag must look like v<version>")

    release = _mapping(manifest.get("release"), "release")
    tag = _string(release.get("tag"), "release.tag")
    if tag != expected_tag:
        raise ReleaseNoteError(
            f"release.tag {tag!r} does not match workflow tag {expected_tag!r}"
        )
    title = _string(release.get("title"), "release.title", min_length=8)
    intended_use = _string(
        release.get("intended_use"), "release.intended_use", min_length=8
    )

    version = expected_tag[1:]
    if not VERSION_RE.fullmatch(version):
        raise ReleaseNoteError("tag version contains unsupported characters")

    server = _mapping(manifest.get("server"), "server")
    server_tag = _string(server.get("tag"), "server.tag")
    if server_tag != expected_tag:
        raise ReleaseNoteError("server.tag must equal release.tag")
    deployment = _string(server.get("deployment"), "server.deployment")

    agent = _mapping(manifest.get("agent"), "agent")
    agent_version = _string(agent.get("version"), "agent.version")
    if agent_version != version:
        raise ReleaseNoteError("agent.version must equal the release tag without 'v'")
    expected_agent_artifacts = [
        "rmm-agent-windows-amd64.exe",
        "rmm-agent-linux-amd64",
        "rmm-agent-darwin-arm64",
    ]
    agent_artifacts = _strings(agent.get("artifacts"), "agent.artifacts")
    if agent_artifacts != expected_agent_artifacts:
        raise ReleaseNoteError(
            "agent.artifacts must list the three release binaries in canonical order"
        )

    installer = _mapping(manifest.get("installer"), "installer")
    installer_version = _string(installer.get("version"), "installer.version")
    if installer_version != version:
        raise ReleaseNoteError("installer.version must equal agent.version")
    installer_filename = _string(installer.get("filename"), "installer.filename")
    expected_installer = f"NodeLinkAgentSetup-{version}.exe"
    if installer_filename != expected_installer:
        raise ReleaseNoteError(
            f"installer.filename must be {expected_installer!r}"
        )

    database = _mapping(manifest.get("database"), "database")
    alembic_revision = _string(
        database.get("alembic_revision"), "database.alembic_revision"
    ).lower()
    if not ALEMBIC_RE.fullmatch(alembic_revision):
        raise ReleaseNoteError("database.alembic_revision is not immutable")
    compatible_from = _strings(
        database.get("compatible_from"),
        "database.compatible_from",
        min_length=1,
    )
    if any(not ALEMBIC_RE.fullmatch(item.lower()) for item in compatible_from):
        raise ReleaseNoteError("database.compatible_from contains invalid revisions")
    migration_policy = _string(
        database.get("migration_policy"), "database.migration_policy", min_length=8
    )

    protocols = _mapping(manifest.get("protocols"), "protocols")
    command_envelopes = _strings(
        protocols.get("command_envelopes"), "protocols.command_envelopes"
    )
    if any(not PROTOCOL_RE.fullmatch(item) for item in command_envelopes):
        raise ReleaseNoteError(
            "protocols.command_envelopes must contain versioned protocol IDs"
        )
    mixed_version_behavior = _string(
        protocols.get("mixed_version_behavior"),
        "protocols.mixed_version_behavior",
        min_length=16,
    )

    known_limitations = _strings(
        manifest.get("known_limitations"), "known_limitations"
    )

    upgrade = _mapping(manifest.get("upgrade"), "upgrade")
    normalized_upgrade = {
        "prerequisites": _strings(
            upgrade.get("prerequisites"), "upgrade.prerequisites"
        ),
        "steps": _strings(upgrade.get("steps"), "upgrade.steps"),
        "verification": _strings(
            upgrade.get("verification"), "upgrade.verification"
        ),
    }

    rollback = _mapping(manifest.get("rollback"), "rollback")
    decision_path = _strings(
        rollback.get("decision_path"), "rollback.decision_path"
    )
    target = _mapping(rollback.get("target"), "rollback.target")
    target_server = _mapping(target.get("server"), "rollback.target.server")
    target_server_tag = _immutable_identifier(
        target_server.get("tag"), "rollback.target.server.tag"
    )
    if not TAG_RE.fullmatch(target_server_tag):
        raise ReleaseNoteError("rollback.target.server.tag must be a version tag")
    target_server_commit = _commit(
        target_server.get("commit"), "rollback.target.server.commit"
    )

    target_agent = _mapping(target.get("agent"), "rollback.target.agent")
    target_agent_version = _immutable_identifier(
        target_agent.get("version"), "rollback.target.agent.version"
    )
    if not VERSION_RE.fullmatch(target_agent_version):
        raise ReleaseNoteError(
            "rollback.target.agent.version must be an immutable version"
        )
    target_agent_sha256s_raw = _mapping(
        target_agent.get("sha256s"), "rollback.target.agent.sha256s"
    )
    if set(target_agent_sha256s_raw) != set(expected_agent_artifacts):
        raise ReleaseNoteError(
            "rollback.target.agent.sha256s must identify all agent artifacts"
        )
    target_agent_sha256s = {
        name: _sha(
            target_agent_sha256s_raw[name],
            f"rollback.target.agent.sha256s.{name}",
        )
        for name in expected_agent_artifacts
    }

    target_installer = _mapping(
        target.get("installer"), "rollback.target.installer"
    )
    target_installer_filename = _immutable_identifier(
        target_installer.get("filename"), "rollback.target.installer.filename"
    )
    if target_installer_filename != (
        f"NodeLinkAgentSetup-{target_agent_version}.exe"
    ):
        raise ReleaseNoteError(
            "rollback.target.installer.filename must match the rollback agent version"
        )
    target_installer_sha256 = _sha(
        target_installer.get("sha256"), "rollback.target.installer.sha256"
    )

    target_database = _mapping(target.get("database"), "rollback.target.database")
    target_revision = _string(
        target_database.get("alembic_revision"),
        "rollback.target.database.alembic_revision",
    ).lower()
    if not ALEMBIC_RE.fullmatch(target_revision):
        raise ReleaseNoteError(
            "rollback.target.database.alembic_revision is invalid"
        )
    backup = _mapping(
        target_database.get("backup_manifest"),
        "rollback.target.database.backup_manifest",
    )
    normalized_backup = {
        "url": _immutable_url(
            backup.get("url"), "rollback.target.database.backup_manifest.url"
        ),
        "sha256": _sha(
            backup.get("sha256"),
            "rollback.target.database.backup_manifest.sha256",
        ),
    }

    target_protocols = _mapping(
        target.get("protocols"), "rollback.target.protocols"
    )
    target_command_envelopes = _strings(
        target_protocols.get("command_envelopes"),
        "rollback.target.protocols.command_envelopes",
    )
    if any(not PROTOCOL_RE.fullmatch(item) for item in target_command_envelopes):
        raise ReleaseNoteError(
            "rollback.target.protocols.command_envelopes contains invalid IDs"
        )

    security = _mapping(manifest.get("security_impact"), "security_impact")
    normalized_security = {
        "summary": _string(
            security.get("summary"), "security_impact.summary", min_length=16
        ),
        "fixed_vulnerabilities": _strings(
            security.get("fixed_vulnerabilities"),
            "security_impact.fixed_vulnerabilities",
        ),
        "new_risks": _strings(
            security.get("new_risks"), "security_impact.new_risks"
        ),
        "operator_actions": _strings(
            security.get("operator_actions"), "security_impact.operator_actions"
        ),
    }

    evidence = _mapping(manifest.get("evidence"), "evidence")
    normalized_evidence: dict[str, dict[str, str]] = {}
    for name in ("backup_verification", "rollback_rehearsal"):
        item = _mapping(evidence.get(name), f"evidence.{name}")
        normalized_evidence[name] = {
            "url": _immutable_url(item.get("url"), f"evidence.{name}.url"),
            "sha256": _sha(item.get("sha256"), f"evidence.{name}.sha256"),
        }

    return {
        "format": FORMAT,
        "release": {
            "tag": tag,
            "title": title,
            "intended_use": intended_use,
        },
        "server": {"tag": server_tag, "deployment": deployment},
        "agent": {
            "version": agent_version,
            "artifacts": agent_artifacts,
        },
        "installer": {
            "version": installer_version,
            "filename": installer_filename,
        },
        "database": {
            "alembic_revision": alembic_revision,
            "compatible_from": [item.lower() for item in compatible_from],
            "migration_policy": migration_policy,
        },
        "protocols": {
            "command_envelopes": command_envelopes,
            "mixed_version_behavior": mixed_version_behavior,
        },
        "known_limitations": known_limitations,
        "upgrade": normalized_upgrade,
        "rollback": {
            "decision_path": decision_path,
            "target": {
                "server": {
                    "tag": target_server_tag,
                    "commit": target_server_commit,
                },
                "agent": {
                    "version": target_agent_version,
                    "sha256s": target_agent_sha256s,
                },
                "installer": {
                    "filename": target_installer_filename,
                    "sha256": target_installer_sha256,
                },
                "database": {
                    "alembic_revision": target_revision,
                    "backup_manifest": normalized_backup,
                },
                "protocols": {
                    "command_envelopes": target_command_envelopes,
                },
            },
        },
        "security_impact": normalized_security,
        "evidence": normalized_evidence,
    }


def _parse_checksum_file(path: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-fA-F]{64})\s+\*?(.+)", line)
        if not match:
            raise ReleaseNoteError(
                f"{path.name}:{line_number} is not a SHA-256 checksum line"
            )
        filename = Path(match.group(2)).name
        if filename in checksums:
            raise ReleaseNoteError(f"{path.name} repeats {filename}")
        checksums[filename] = match.group(1).lower()
    return checksums


def finalize_release(
    manifest: dict[str, Any],
    manifest_path: Path,
    artifact_dir: Path,
    source_sha: str,
    repository: str,
    run_url: str,
) -> tuple[dict[str, Any], str]:
    """Bind a validated source manifest to the built release artifacts."""
    normalized = validate_manifest(manifest, manifest["release"]["tag"])
    source_sha = _commit(source_sha, "source_sha")
    if not REPOSITORY_RE.fullmatch(repository):
        raise ReleaseNoteError("repository must use owner/name form")
    run_url = _immutable_url(run_url, "run_url")

    version = normalized["agent"]["version"]
    sbom_name = f"nodelink-{version}.spdx.json"
    checksum_name = "SHA256SUMS.txt"
    installer_name = normalized["installer"]["filename"]
    installer_checksum_name = f"{installer_name}.sha256"
    artifact_names = [
        *normalized["agent"]["artifacts"],
        sbom_name,
        checksum_name,
        installer_name,
        installer_checksum_name,
    ]
    paths = {name: artifact_dir / name for name in artifact_names}
    missing = [name for name, path in paths.items() if not path.is_file()]
    if missing:
        raise ReleaseNoteError(
            "release artifacts are missing: " + ", ".join(sorted(missing))
        )

    digests = {name: _sha256(path) for name, path in paths.items()}
    agent_checksums = _parse_checksum_file(paths[checksum_name])
    for name in [*normalized["agent"]["artifacts"], sbom_name]:
        if agent_checksums.get(name) != digests[name]:
            raise ReleaseNoteError(
                f"{checksum_name} does not match built artifact {name}"
            )
    installer_checksums = _parse_checksum_file(paths[installer_checksum_name])
    if installer_checksums != {installer_name: digests[installer_name]}:
        raise ReleaseNoteError(
            f"{installer_checksum_name} does not match {installer_name}"
        )

    tag = normalized["release"]["tag"]
    manifest_digest = _source_manifest_sha256(manifest_path)
    manifest_url = (
        f"https://github.com/{repository}/blob/{source_sha}/"
        f"release-notes/{quote(tag, safe='')}.json"
    )
    release_base = (
        f"https://github.com/{repository}/releases/download/{quote(tag, safe='')}"
    )
    asset_urls = {
        name: f"{release_base}/{quote(name, safe='.-')}" for name in artifact_names
    }
    attested_names = [*normalized["agent"]["artifacts"], installer_name]
    provenance = [
        {
            "artifact": name,
            "url": (
                f"https://api.github.com/repos/{repository}/attestations/"
                f"sha256:{digests[name]}"
            ),
            "verify": f"gh attestation verify {name} --repo {repository}",
        }
        for name in attested_names
    ]

    evidence = {
        "format": EVIDENCE_FORMAT,
        "manifest_sha256": manifest_digest,
        "release": normalized["release"],
        "source": {
            "repository": repository,
            "tag": tag,
            "commit": source_sha,
            "workflow_run": run_url,
            "manifest": {
                "url": manifest_url,
                "sha256": manifest_digest,
            },
        },
        "server": {
            **normalized["server"],
            "commit": source_sha,
        },
        "agent": {
            "version": normalized["agent"]["version"],
            "artifacts": [
                {
                    "filename": name,
                    "sha256": digests[name],
                    "url": asset_urls[name],
                }
                for name in normalized["agent"]["artifacts"]
            ],
        },
        "installer": {
            "version": normalized["installer"]["version"],
            "filename": installer_name,
            "sha256": digests[installer_name],
            "url": asset_urls[installer_name],
        },
        "database": normalized["database"],
        "protocols": normalized["protocols"],
        "known_limitations": normalized["known_limitations"],
        "upgrade": normalized["upgrade"],
        "rollback": normalized["rollback"],
        "security_impact": normalized["security_impact"],
        "evidence": {
            "ci": {"url": run_url, "source_commit": source_sha},
            "checksums": {
                "url": asset_urls[checksum_name],
                "sha256": digests[checksum_name],
            },
            "installer_checksum": {
                "url": asset_urls[installer_checksum_name],
                "sha256": digests[installer_checksum_name],
            },
            "sbom": {
                "url": asset_urls[sbom_name],
                "sha256": digests[sbom_name],
            },
            "provenance": provenance,
            **normalized["evidence"],
        },
    }
    return evidence, render_markdown(evidence)


def _bullet_lines(items: list[str]) -> list[str]:
    return [f"- {item}" for item in items]


def _numbered_lines(items: list[str]) -> list[str]:
    return [f"{index}. {item}" for index, item in enumerate(items, start=1)]


def render_markdown(evidence: dict[str, Any]) -> str:
    """Render the validated evidence as the GitHub Release body."""
    release = evidence["release"]
    source = evidence["source"]
    rollback_target = evidence["rollback"]["target"]
    lines = [
        f"# {release['title']}",
        "",
        release["intended_use"],
        "",
        "## Immutable release identity",
        "",
        f"- Tag: `{source['tag']}`",
        f"- Server source commit: [`{source['commit']}`]"
        f"(https://github.com/{source['repository']}/commit/{source['commit']})",
        f"- Release workflow: [run evidence]({source['workflow_run']})",
        f"- Source manifest: [release-notes/{source['tag']}.json]"
        f"({source['manifest']['url']}) "
        f"(SHA-256 `{source['manifest']['sha256']}`)",
        "",
        "## Released components",
        "",
        f"- Agent version: `{evidence['agent']['version']}`",
        f"- Installer version: `{evidence['installer']['version']}`",
        "",
        "| Component | Version / file | SHA-256 |",
        "|---|---|---|",
    ]
    for artifact in evidence["agent"]["artifacts"]:
        lines.append(
            f"| Agent | [{artifact['filename']}]({artifact['url']}) | "
            f"`{artifact['sha256']}` |"
        )
    installer = evidence["installer"]
    lines.append(
        f"| Windows installer | [{installer['filename']}]({installer['url']}) | "
        f"`{installer['sha256']}` |"
    )
    lines.extend(
        [
            f"| Server | `{evidence['server']['tag']}` / "
            f"`{evidence['server']['commit']}` | source commit |",
            "",
            "## Supported platforms",
            "",
            "- Supported product target: `windows/amd64` (x64).",
            "- Development-only builds: `linux/amd64`, `darwin/arm64`.",
            "- Support policy: [Windows support matrix]"
            f"(https://github.com/{source['repository']}/blob/"
            f"{source['commit']}/docs/WINDOWS-SUPPORT-MATRIX.md).",
            "- Release-specific platform exceptions are listed under "
            "Known limitations.",
            "",
            "## Schema and protocol compatibility",
            "",
            f"- Required Alembic revision: `{evidence['database']['alembic_revision']}`",
            "- Supported upgrade origins: "
            + ", ".join(
                f"`{item}`" for item in evidence["database"]["compatible_from"]
            ),
            f"- Migration policy: {evidence['database']['migration_policy']}",
            "- Command envelopes: "
            + ", ".join(
                f"`{item}`" for item in evidence["protocols"]["command_envelopes"]
            ),
            f"- Mixed-version behavior: {evidence['protocols']['mixed_version_behavior']}",
            "",
            "## Known limitations",
            "",
            *_bullet_lines(evidence["known_limitations"]),
            "",
            "## Upgrade",
            "",
            "### Prerequisites",
            "",
            *_bullet_lines(evidence["upgrade"]["prerequisites"]),
            "",
            "### Steps",
            "",
            *_numbered_lines(evidence["upgrade"]["steps"]),
            "",
            "### Verification",
            "",
            *_bullet_lines(evidence["upgrade"]["verification"]),
            "",
            "## Rollback",
            "",
            "### Decision path",
            "",
            *_numbered_lines(evidence["rollback"]["decision_path"]),
            "",
            "### Last-known-good target",
            "",
            f"- Server: `{rollback_target['server']['tag']}` at "
            f"`{rollback_target['server']['commit']}`",
            f"- Agent version: `{rollback_target['agent']['version']}`",
            *[
                f"  - `{name}`: `{digest}`"
                for name, digest in rollback_target["agent"]["sha256s"].items()
            ],
            f"- Installer: `{rollback_target['installer']['filename']}` at "
            f"`{rollback_target['installer']['sha256']}`",
            f"- Database: Alembic `{rollback_target['database']['alembic_revision']}`; "
            f"[backup manifest]({rollback_target['database']['backup_manifest']['url']}) "
            f"SHA-256 `{rollback_target['database']['backup_manifest']['sha256']}`",
            "- Command envelopes: "
            + ", ".join(
                f"`{item}`"
                for item in rollback_target["protocols"]["command_envelopes"]
            ),
            "",
            "## Security impact",
            "",
            evidence["security_impact"]["summary"],
            "",
            "### Fixed vulnerabilities",
            "",
            *_bullet_lines(evidence["security_impact"]["fixed_vulnerabilities"]),
            "",
            "### New or retained risks",
            "",
            *_bullet_lines(evidence["security_impact"]["new_risks"]),
            "",
            "### Required operator actions",
            "",
            *_bullet_lines(evidence["security_impact"]["operator_actions"]),
            "",
            "## Release evidence",
            "",
            f"- [Checksums]({evidence['evidence']['checksums']['url']})",
            f"- [Installer checksum]"
            f"({evidence['evidence']['installer_checksum']['url']})",
            f"- [SPDX SBOM]({evidence['evidence']['sbom']['url']})",
            f"- [CI and release workflow]({evidence['evidence']['ci']['url']})",
            f"- [Backup verification]"
            f"({evidence['evidence']['backup_verification']['url']}) "
            f"(SHA-256 `{evidence['evidence']['backup_verification']['sha256']}`)",
            f"- [Rollback rehearsal]"
            f"({evidence['evidence']['rollback_rehearsal']['url']}) "
            f"(SHA-256 `{evidence['evidence']['rollback_rehearsal']['sha256']}`)",
            "",
            "### Build provenance",
            "",
        ]
    )
    for item in evidence["evidence"]["provenance"]:
        lines.append(
            f"- [{item['artifact']}]({item['url']}): `{item['verify']}`"
        )
    lines.extend(
        [
            "",
            "> This body was generated only after the release manifest and "
            "built artifact checksums passed fail-closed validation.",
            "",
        ]
    )
    return "\n".join(lines)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument(
        "--phase", choices=("preflight", "finalize"), default="preflight"
    )
    parser.add_argument("--artifact-dir", type=Path)
    parser.add_argument("--source-sha")
    parser.add_argument("--repository")
    parser.add_argument("--run-url")
    parser.add_argument("--output-notes", type=Path)
    parser.add_argument("--output-evidence", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        manifest = load_manifest(args.manifest)
        normalized = validate_manifest(manifest, args.tag)
        if args.phase == "preflight":
            print(
                json.dumps(
                    {
                        "status": "valid",
                        "tag": normalized["release"]["tag"],
                        "manifest_sha256": _source_manifest_sha256(args.manifest),
                    },
                    sort_keys=True,
                )
            )
            return 0

        missing_args = [
            name
            for name in (
                "artifact_dir",
                "source_sha",
                "repository",
                "run_url",
                "output_notes",
                "output_evidence",
            )
            if getattr(args, name) is None
        ]
        if missing_args:
            raise ReleaseNoteError(
                "finalize requires: " + ", ".join(missing_args)
            )
        evidence, markdown = finalize_release(
            manifest,
            args.manifest,
            args.artifact_dir,
            args.source_sha,
            args.repository,
            args.run_url,
        )
        args.output_notes.parent.mkdir(parents=True, exist_ok=True)
        args.output_evidence.parent.mkdir(parents=True, exist_ok=True)
        args.output_notes.write_text(markdown, encoding="utf-8", newline="\n")
        args.output_evidence.write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        print(
            json.dumps(
                {
                    "status": "finalized",
                    "tag": evidence["release"]["tag"],
                    "source_commit": evidence["source"]["commit"],
                    "artifact_count": (
                        len(evidence["agent"]["artifacts"]) + 1
                    ),
                },
                sort_keys=True,
            )
        )
        return 0
    except ReleaseNoteError as exc:
        print(f"release-notes: invalid: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
