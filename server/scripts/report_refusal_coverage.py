# SPDX-License-Identifier: AGPL-3.0-only
"""Report which ``raise HTTPException`` sites the test suite never triggers.

Line coverage hides refusal branches: a router can be 90% covered while most of
its 403/404/409 paths have never run. This script reads a coverage.py JSON
report (``pytest --cov=app --cov-branch --cov-report=json``), finds every
``raise HTTPException(...)`` in ``app/api/*.py`` and ``app/main.py`` with the
AST, and reports the ones whose line never executed, grouped by router.

Usage (from ``server/``)::

    python scripts/report_refusal_coverage.py coverage.json
    python scripts/report_refusal_coverage.py coverage.json --list
    python scripts/report_refusal_coverage.py coverage.json --max-uncovered 20

Exits 1 when ``--max-uncovered`` is given and the uncovered count exceeds it.
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

SERVER_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class RaiseSite:
    path: str
    line: int
    function: str


def _is_http_exception(node: ast.Raise) -> bool:
    call = node.exc
    if not isinstance(call, ast.Call):
        return False
    func = call.func
    if isinstance(func, ast.Name):
        return func.id == "HTTPException"
    return isinstance(func, ast.Attribute) and func.attr == "HTTPException"


def raise_sites(root: Path = SERVER_ROOT) -> list[RaiseSite]:
    files = sorted((root / "app" / "api").glob("*.py")) + [root / "app" / "main.py"]
    sites: list[RaiseSite] = []
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        rel = path.relative_to(root).as_posix()
        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(func):
                if isinstance(node, ast.Raise) and _is_http_exception(node):
                    sites.append(RaiseSite(rel, node.lineno, func.name))
    # A raise inside a nested function is visited once per enclosing function;
    # keep the innermost (last-visited) name for each line.
    unique = {(site.path, site.line): site for site in sites}
    return sorted(unique.values(), key=lambda site: (site.path, site.line))


def executed_lines(report: dict) -> dict[str, set[int]]:
    lines: dict[str, set[int]] = {}
    for name, data in report["files"].items():
        lines[Path(name).as_posix()] = set(data["executed_lines"])
    return lines


def uncovered(sites: list[RaiseSite], executed: dict[str, set[int]]) -> list[RaiseSite]:
    missing = []
    for site in sites:
        hit = next(
            (lines for name, lines in executed.items() if name.endswith(site.path)),
            set(),
        )
        if site.line not in hit:
            missing.append(site)
    return missing


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("coverage_json", type=Path)
    parser.add_argument("--list", action="store_true", help="list every uncovered site")
    parser.add_argument("--max-uncovered", type=int, default=None)
    args = parser.parse_args(argv)

    report = json.loads(args.coverage_json.read_text(encoding="utf-8"))
    sites = raise_sites()
    missing = uncovered(sites, executed_lines(report))

    totals = Counter(Path(site.path).stem for site in sites)
    misses = Counter(Path(site.path).stem for site in missing)
    print(f"HTTPException sites: {len(sites)}  untriggered: {len(missing)}")
    for router in sorted(totals, key=lambda name: (-misses[name], name)):
        print(f"  {router:<18} {misses[router]:>3} / {totals[router]}")
    if args.list:
        for site in missing:
            print(f"{site.path}:{site.line} {site.function}")

    if args.max_uncovered is not None and len(missing) > args.max_uncovered:
        print(
            f"FAIL: {len(missing)} untriggered HTTPException sites "
            f"(limit {args.max_uncovered})",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
