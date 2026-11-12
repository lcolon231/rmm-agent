# SPDX-License-Identifier: AGPL-3.0-only
"""Regenerate (or --check) the committed public API contract files (#72).

    python scripts/export_public_contracts.py          # rewrite
    python scripts/export_public_contracts.py --check  # exit 1 on drift
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core import public_contracts  # noqa: E402
from app.main import app  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail instead of writing")
    args = parser.parse_args()
    outputs = {
        public_contracts.OPENAPI_PATH: public_contracts.build_openapi(app),
        public_contracts.WEBHOOK_VECTORS_PATH: public_contracts.build_webhook_vectors(),
    }
    drift = False
    for path, document in outputs.items():
        rendered = public_contracts.render(document)
        # Compare newline-normalized: a Windows checkout may hold CRLF copies.
        current = (
            path.read_text(encoding="utf-8").replace("\r\n", "\n") if path.exists() else None
        )
        if current == rendered:
            continue
        drift = True
        if args.check:
            print(f"out of date: {path}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(rendered, encoding="utf-8", newline="\n")
            print(f"wrote {path}")
    return 1 if (drift and args.check) else 0


if __name__ == "__main__":
    raise SystemExit(main())
