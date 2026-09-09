#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Small, auditable repository license checks for CI."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SUFFIXES = {".go", ".py", ".sh", ".ps1", ".js", ".ts", ".tsx", ".jsx"}
EXCLUDED_PARTS = {".git", ".venv", "vendor", "node_modules"}


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "-c", f"safe.directory={ROOT.as_posix()}", "ls-files"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [ROOT / line for line in result.stdout.splitlines()]


def has_spdx(path: Path) -> bool:
    lines = path.read_text(encoding="utf-8").splitlines()[:16]
    return any("SPDX-License-Identifier: AGPL-3.0-only" in line for line in lines)


def main() -> int:
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    if not license_text.startswith("                    GNU AFFERO GENERAL PUBLIC LICENSE"):
        raise SystemExit("LICENSE is missing the official AGPL-3.0 text")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if "AGPL-3.0-only" not in readme:
        raise SystemExit("README.md does not declare AGPL-3.0-only")
    if "TBD" in readme or "private during initial development" in readme:
        raise SystemExit("README.md contains stale licensing language")

    for metadata in (ROOT / "package.json", ROOT / "pyproject.toml", ROOT / "setup.cfg"):
        if not metadata.exists():
            continue
        text = metadata.read_text(encoding="utf-8")
        if metadata.suffix == ".json" and json.loads(text).get("license") != "AGPL-3.0-only":
            raise SystemExit(f"{metadata} must declare AGPL-3.0-only")
        if metadata.suffix != ".json" and "AGPL-3.0-only" not in text:
            raise SystemExit(f"{metadata} must declare AGPL-3.0-only")

    missing: list[str] = []
    for path in tracked_files():
        if path.suffix not in SOURCE_SUFFIXES or any(part in EXCLUDED_PARTS for part in path.parts):
            continue
        if path.name == "__init__.py":
            continue
        if not has_spdx(path):
            missing.append(str(path.relative_to(ROOT)))
    if missing:
        raise SystemExit("Missing SPDX headers:\n" + "\n".join(missing))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
