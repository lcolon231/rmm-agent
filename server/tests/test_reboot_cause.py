# SPDX-License-Identifier: AGPL-3.0-only
"""Correlated update evidence for pending-restart alert details (#230)."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from app.core import monitoring
from app.models.models import AgentInventorySnapshot
from app.schemas.inventory import InventorySection
from app.schemas.monitoring import AlertDetailOut, AlertOut, RebootCauseOut


NOW = datetime(2026, 9, 2, 12, tzinfo=timezone.utc)


def _snapshot(payload: dict, *, received_at: datetime = NOW) -> AgentInventorySnapshot:
    return AgentInventorySnapshot(
        id="snapshot-1",
        agent_id="agent-1",
        section=InventorySection.windows_updates.value,
        status="ok",
        schema_version=1,
        content_hash="a" * 64,
        byte_size=1,
        payload=payload,
        collected_at=received_at - timedelta(minutes=1),
        received_at=received_at,
    )


def test_reboot_cause_requires_an_inventory_snapshot() -> None:
    assert monitoring.REBOOT_CAUSE_LOOKBACK == timedelta(days=7)
    assert monitoring.derive_reboot_cause(None, None, NOW - timedelta(days=7)) is None


def test_reboot_cause_correlates_flagged_updates_and_recent_installs(
    monkeypatch,
) -> None:
    monkeypatch.setattr(monitoring, "_now", lambda: NOW)
    installed = [
        {
            "kb_id": f"KB{index:04d}",
            "title": f"Update {index}",
            "installed_on": (NOW - timedelta(hours=index)).isoformat(),
        }
        for index in range(12, 0, -1)
    ]
    installed.extend(
        [
            {
                "kb_id": "KB-OLD",
                "title": "Outside lookback",
                "installed_on": (NOW - timedelta(days=8)).isoformat(),
            },
            {
                "kb_id": "KB-FUTURE",
                "title": "Future clock",
                "installed_on": (NOW + timedelta(minutes=1)).isoformat(),
            },
            {"kb_id": "KB-UNDATED", "title": "No timestamp"},
        ]
    )
    snapshot = _snapshot(
        {
            "scanned_at": (NOW - timedelta(minutes=2)).isoformat(),
            "reboot_required": True,
            "missing": [
                {
                    "kb_id": "KB-PENDING",
                    "title": "Pending restart update",
                    "reboot_required": True,
                },
                {
                    "kb_id": "KB-NORMAL",
                    "title": "Normal missing update",
                    "reboot_required": False,
                },
            ],
            "installed": installed,
        }
    )

    result = monitoring.derive_reboot_cause(
        snapshot,
        {"reason": "reboot_pending"},  # pre-source-reporting agent detail
        NOW - monitoring.REBOOT_CAUSE_LOOKBACK,
    )

    assert result is not None
    assert [row["kb_id"] for row in result.reboot_flagged_updates] == [
        "KB-PENDING"
    ]
    assert [row["kb_id"] for row in result.recent_installs] == [
        f"KB{index:04d}" for index in range(1, 11)
    ]
    assert result.system_reboot_required is True
    assert result.scanned_at == NOW - timedelta(minutes=2)
    assert result.snapshot_received_at == NOW

    # Layer 2 is evidence only. A missing sources object must not manufacture a
    # categorical "not update-related" answer for an older agent.
    assert set(asdict(result)) == {
        "reboot_flagged_updates",
        "recent_installs",
        "system_reboot_required",
        "scanned_at",
        "snapshot_received_at",
    }


def test_reboot_cause_keeps_empty_evidence_distinct_from_no_snapshot(monkeypatch) -> None:
    monkeypatch.setattr(monitoring, "_now", lambda: NOW)
    result = monitoring.derive_reboot_cause(
        _snapshot(
            {
                "scanned_at": None,
                "reboot_required": False,
                "missing": [],
                "installed": [],
            }
        ),
        None,
        NOW - monitoring.REBOOT_CAUSE_LOOKBACK,
    )

    assert result is not None
    assert result.reboot_flagged_updates == []
    assert result.recent_installs == []
    assert result.system_reboot_required is False
    assert result.scanned_at is None


def test_reboot_cause_output_contract_is_detail_only(monkeypatch) -> None:
    monkeypatch.setattr(monitoring, "_now", lambda: NOW)
    cause = monitoring.derive_reboot_cause(
        _snapshot(
            {
                "scanned_at": NOW.isoformat(),
                "reboot_required": True,
                "missing": [
                    {
                        "kb_id": "KB-PENDING",
                        "title": "Pending update",
                        "reboot_required": True,
                    }
                ],
                "installed": [],
            }
        ),
        None,
        NOW - monitoring.REBOOT_CAUSE_LOOKBACK,
    )

    payload = RebootCauseOut.model_validate(cause).model_dump()
    assert payload["reboot_flagged_updates"][0]["kb_id"] == "KB-PENDING"
    assert payload["snapshot_received_at"] == NOW
    assert "last_result_detail" not in AlertOut.model_fields
    assert "reboot_cause" not in AlertOut.model_fields
    assert AlertDetailOut.model_fields["last_result_detail"].default is None
    assert AlertDetailOut.model_fields["reboot_cause"].default is None
