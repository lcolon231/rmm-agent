# SPDX-License-Identifier: AGPL-3.0-only
"""Clean-room verification of an externally published audit anchor.

This proves — with NO write access to (and, optionally, no read access to) the
NodeLink database — that a published anchor artifact commits to a specific set
of audit events. Run it against the artifact you downloaded FROM the external
destination (e.g. `aws s3 cp s3://bucket/nodelink/anchors/anchor-....json .`)
plus the event hashes, which you can export read-only.

Two inputs:
  --artifact FILE   the canonical anchor document published externally (JSON
                    with merkle_root, event_count, last_event_id)
  --event-hashes FILE
                    newline- or JSON-array-delimited event_hash values in
                    ascending seq order (the covered prefix). Export with, e.g.:
                      psql -tAc "SELECT event_hash FROM audit_events
                                 ORDER BY seq LIMIT <event_count>" > hashes.txt

It recomputes the Merkle root from the event hashes using the exact
construction in app/core/anchor.py and checks it equals the artifact's root and
that the artifact covers the expected count. Exit 0 = the external anchor and
the events agree; exit 1 = they do not (history was altered, or the wrong
inputs were supplied).

The Merkle construction is reproduced here on purpose: a verifier must not have
to import NodeLink to trust it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys


def merkle_root(leaf_hashes: list[str]) -> str:
    if not leaf_hashes:
        raise ValueError("cannot build a Merkle root over zero leaves")
    level = [bytes.fromhex(h) for h in leaf_hashes]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(hashlib.sha256(level[i] + level[i + 1]).digest())
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
    return level[0].hex()


def load_hashes(path: str) -> list[str]:
    text = open(path, encoding="utf-8").read().strip()
    if text.startswith("["):
        return [str(h).strip() for h in json.loads(text)]
    return [line.strip() for line in text.splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--artifact", required=True,
                        help="the published anchor document (downloaded externally)")
    parser.add_argument("--event-hashes", required=True,
                        help="event_hash values in seq order for the covered prefix")
    args = parser.parse_args(argv)

    artifact = json.load(open(args.artifact, encoding="utf-8"))
    root = artifact.get("merkle_root")
    expected_count = artifact.get("event_count")
    hashes = load_hashes(args.event_hashes)

    problems = []
    if expected_count is not None and len(hashes) != expected_count:
        problems.append(
            f"supplied {len(hashes)} event hashes but the artifact covers {expected_count}"
        )
    try:
        recomputed = merkle_root(hashes)
    except ValueError as exc:
        problems.append(str(exc))
        recomputed = None
    if recomputed is not None and recomputed != root:
        problems.append(f"recomputed root {recomputed} != published root {root}")

    if problems:
        for p in problems:
            print(f"verify-anchor: FAIL {p}", file=sys.stderr)
        return 1
    print(f"verify-anchor: OK — {len(hashes)} events reproduce published root {root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
