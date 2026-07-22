# SPDX-License-Identifier: AGPL-3.0-only
"""Release rollback compatibility decisions and fail-closed paths."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts.plan_release_rollback import build_plan

SERVER_ROOT = Path(__file__).resolve().parents[1]
PLANNER = SERVER_ROOT / "scripts" / "plan_release_rollback.py"


def _plan(**overrides):
    values = {
        "current_schema_revision": "0008",
        "backup_schema_revision": "0008",
        "target_schema_revision": "0008",
        "target_server_version": "v1.2.3",
        "target_agent_version": "v1.2.3",
        "target_installer_version": "NodeLinkAgentSetup-1.2.3.exe",
        "agent_rollout_paused": True,
        "accept_data_loss": False,
    }
    values.update(overrides)
    return build_plan(**values)


def test_same_schema_allows_component_redeploy_without_restore():
    plan = _plan()
    assert plan["status"] == "ready"
    assert plan["action"] == "redeploy_without_database_restore"
    assert plan["restore_required"] is False


def test_schema_rollback_requires_matching_backup_and_data_loss_acceptance():
    blocked = _plan(current_schema_revision="0009")
    assert blocked["status"] == "blocked"
    assert any("data loss" in reason for reason in blocked["reasons"])

    ready = _plan(current_schema_revision="0009", accept_data_loss=True)
    assert ready["status"] == "ready"
    assert ready["action"] == "restore_backup_then_redeploy"


def test_incompatible_backup_fails_closed():
    plan = _plan(
        current_schema_revision="0009",
        backup_schema_revision="0007",
        accept_data_loss=True,
    )
    assert plan["status"] == "blocked"
    assert any("does not match" in reason for reason in plan["reasons"])


def test_unpaused_agent_rollout_fails_closed():
    plan = _plan(agent_rollout_paused=False)
    assert plan["status"] == "blocked"
    assert any("could be reapplied" in reason for reason in plan["reasons"])


def test_unnamed_component_fails_closed():
    plan = _plan(target_installer_version="   ")
    assert plan["status"] == "blocked"
    assert any("target installer version" in reason for reason in plan["reasons"])


def test_cli_rejects_non_nodelink_manifest(tmp_path: Path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"schema_revision": "0008"}', encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(PLANNER),
            "--backup-manifest",
            str(manifest),
            "--current-schema-revision",
            "0008",
            "--target-schema-revision",
            "0008",
            "--target-server-version",
            "v1",
            "--target-agent-version",
            "v1",
            "--target-installer-version",
            "installer-v1",
            "--agent-rollout-paused",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "invalid backup manifest" in result.stderr


def test_cli_writes_named_component_evidence(tmp_path: Path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "format": "nodelink-backup-manifest",
                "schema_revision": "0008",
            }
        ),
        encoding="utf-8",
    )
    evidence = tmp_path / "rollback-plan.json"
    result = subprocess.run(
        [
            sys.executable,
            str(PLANNER),
            "--backup-manifest",
            str(manifest),
            "--current-schema-revision",
            "0009",
            "--target-schema-revision",
            "0008",
            "--target-server-version",
            "server-n",
            "--target-agent-version",
            "agent-n",
            "--target-installer-version",
            "installer-n",
            "--agent-rollout-paused",
            "--accept-data-loss",
            "--evidence-output",
            str(evidence),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    plan = json.loads(evidence.read_text(encoding="utf-8"))
    assert plan["target"] == {
        "server_version": "server-n",
        "agent_version": "agent-n",
        "installer_version": "installer-n",
        "schema_revision": "0008",
    }
    assert plan["action"] == "restore_backup_then_redeploy"
