#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fail-closed release rollback compatibility planner.

The planner never changes a database or deployment. It combines the schema
revision in an encrypted-backup manifest with the operator's release-specific
component choices and records whether a rollback may proceed.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def build_plan(
    *,
    current_schema_revision: str,
    backup_schema_revision: str,
    target_schema_revision: str,
    target_server_version: str,
    target_agent_version: str,
    target_installer_version: str,
    agent_rollout_paused: bool,
    accept_data_loss: bool,
) -> dict[str, Any]:
    """Return a deterministic rollback decision for the supplied revisions."""
    named_values = {
        "current schema revision": current_schema_revision,
        "backup schema revision": backup_schema_revision,
        "target schema revision": target_schema_revision,
        "target server version": target_server_version,
        "target agent version": target_agent_version,
        "target installer version": target_installer_version,
    }
    missing = [name for name, value in named_values.items() if not value.strip()]
    reasons: list[str] = []
    if missing:
        reasons.append("missing required value(s): " + ", ".join(missing))
    if not agent_rollout_paused:
        reasons.append(
            "automatic/external agent rollout is not confirmed paused; "
            "the bad version could be reapplied"
        )

    restore_required = current_schema_revision != target_schema_revision
    if restore_required and backup_schema_revision != target_schema_revision:
        reasons.append(
            "backup schema revision does not match the target server schema; "
            "in-place Alembic downgrade is unsupported"
        )
    if restore_required and not accept_data_loss:
        reasons.append(
            "schema rollback requires restore from backup and explicit acceptance "
            "of post-backup data loss"
        )

    safe = not reasons
    if not safe:
        action = "blocked"
    elif restore_required:
        action = "restore_backup_then_redeploy"
    else:
        action = "redeploy_without_database_restore"

    return {
        "format": "nodelink-release-rollback-plan",
        "version": 1,
        "created_at_utc": datetime.now(UTC).isoformat(),
        "status": "ready" if safe else "blocked",
        "action": action,
        "current_schema_revision": current_schema_revision,
        "backup_schema_revision": backup_schema_revision,
        "target": {
            "server_version": target_server_version,
            "agent_version": target_agent_version,
            "installer_version": target_installer_version,
            "schema_revision": target_schema_revision,
        },
        "agent_rollout_paused": agent_rollout_paused,
        "restore_required": restore_required,
        "data_loss_accepted": accept_data_loss,
        "reasons": reasons,
    }


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup-manifest", required=True, type=Path)
    parser.add_argument("--current-schema-revision", required=True)
    parser.add_argument("--target-schema-revision", required=True)
    parser.add_argument("--target-server-version", required=True)
    parser.add_argument("--target-agent-version", required=True)
    parser.add_argument("--target-installer-version", required=True)
    parser.add_argument("--agent-rollout-paused", action="store_true")
    parser.add_argument("--accept-data-loss", action="store_true")
    parser.add_argument("--evidence-output", type=Path)
    args = parser.parse_args()

    try:
        manifest = json.loads(args.backup_manifest.read_text(encoding="utf-8"))
        if manifest.get("format") != "nodelink-backup-manifest":
            raise ValueError("not a NodeLink backup manifest")
        backup_revision = manifest["schema_revision"]
        if not isinstance(backup_revision, str):
            raise ValueError("manifest schema_revision must be a string")
    except (OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        print(f"rollback-plan: invalid backup manifest: {exc}", file=sys.stderr)
        return 2

    plan = build_plan(
        current_schema_revision=args.current_schema_revision,
        backup_schema_revision=backup_revision,
        target_schema_revision=args.target_schema_revision,
        target_server_version=args.target_server_version,
        target_agent_version=args.target_agent_version,
        target_installer_version=args.target_installer_version,
        agent_rollout_paused=args.agent_rollout_paused,
        accept_data_loss=args.accept_data_loss,
    )
    rendered = json.dumps(plan, indent=2)
    print(rendered)
    if args.evidence_output:
        _atomic_write_json(args.evidence_output, plan)
        print(f"rollback-plan: evidence wrote {args.evidence_output}", file=sys.stderr)
    return 0 if plan["status"] == "ready" else 2


if __name__ == "__main__":
    raise SystemExit(main())
