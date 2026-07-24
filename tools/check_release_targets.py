#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fail if release build targets drift from the declared architecture list.

The single source of truth is ``agent/supported-targets.txt``. This checker
verifies that:

  * every ``GOOS=.. GOARCH=..`` build in ``agent/build.sh`` corresponds to a
    declared target, and every declared target is built there;
  * every ``rmm-agent-<goos>-<goarch>`` artifact referenced in the release
    workflow corresponds to a declared target;
  * at least one ``supported`` target exists and it is windows/amd64 (the
    primary product target).

Drift in either direction fails CI, so an architecture cannot be added or
removed from what NodeLink ships without an explicit, reviewed change to the
declared list (and, by policy, to docs/WINDOWS-SUPPORT-MATRIX.md).

Usage:  python3 tools/check_release_targets.py   (exit 0 = OK, 1 = drift)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DECLARED = ROOT / "agent" / "supported-targets.txt"
BUILD_SH = ROOT / "agent" / "build.sh"
RELEASE_YML = ROOT / ".github" / "workflows" / "release.yml"


def parse_declared() -> dict[str, str]:
    targets: dict[str, str] = {}
    for line in DECLARED.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2 or "/" not in parts[0]:
            raise SystemExit(f"malformed line in {DECLARED.name}: {line!r}")
        target, klass = parts
        if klass not in ("supported", "dev"):
            raise SystemExit(f"unknown class {klass!r} in {DECLARED.name}: {line!r}")
        targets[target] = klass
    if not targets:
        raise SystemExit(f"{DECLARED.name} declares no targets")
    return targets


def build_sh_targets() -> set[str]:
    text = BUILD_SH.read_text()
    # Match "GOOS=windows GOARCH=amd64" (env-prefixed go build invocations).
    pairs = re.findall(r"GOOS=(\w+)\s+GOARCH=(\w+)", text)
    return {f"{goos}/{goarch}" for goos, goarch in pairs}


def release_artifact_targets() -> set[str]:
    text = RELEASE_YML.read_text()
    # Match artifact basenames rmm-agent-<goos>-<goarch>[.exe].
    names = re.findall(r"rmm-agent-([a-z0-9]+)-([a-z0-9]+)", text)
    return {f"{goos}/{goarch}" for goos, goarch in names}


def main() -> int:
    declared = parse_declared()
    declared_set = set(declared)
    errors: list[str] = []

    built = build_sh_targets()
    if built != declared_set:
        missing = declared_set - built
        extra = built - declared_set
        if missing:
            errors.append(f"declared but not built in build.sh: {sorted(missing)}")
        if extra:
            errors.append(f"built in build.sh but not declared: {sorted(extra)}")

    artifacts = release_artifact_targets()
    undeclared_artifacts = artifacts - declared_set
    if undeclared_artifacts:
        errors.append(
            f"release.yml ships undeclared targets: {sorted(undeclared_artifacts)}"
        )

    supported = {t for t, k in declared.items() if k == "supported"}
    if "windows/amd64" not in supported:
        errors.append("windows/amd64 must be declared as a 'supported' target")

    if errors:
        print("Release target drift detected (issue #116):")
        for e in errors:
            print(f"  - {e}")
        print(
            "\nUpdate agent/supported-targets.txt AND docs/WINDOWS-SUPPORT-MATRIX.md "
            "together, then adjust build.sh / release.yml to match."
        )
        return 1

    print(f"Release targets OK: {sorted(declared_set)} (supported: {sorted(supported)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
