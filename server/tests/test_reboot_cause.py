# SPDX-License-Identifier: AGPL-3.0-only
"""Reboot cause for pending-restart alert details (#230 evidence, #231 verdict)."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_reboot_cause.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

from app.core import monitoring  # noqa: E402
from app.models.models import AgentInventorySnapshot  # noqa: E402
from app.schemas.inventory import InventorySection  # noqa: E402
from app.schemas.monitoring import (  # noqa: E402
    AgentCheckResultIn,
    AlertDetailOut,
    AlertOut,
    RebootCauseOut,
)


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


def _detail(
    *,
    component_based_servicing: bool = False,
    windows_update: bool = False,
    pending_file_rename: bool = False,
    count: object = None,
) -> dict:
    """A reboot result detail as a source-reporting agent sends it."""
    detail: dict = {
        "check_type": "reboot_pending",
        "reason": "reboot_pending",
        "sources": {
            "component_based_servicing": component_based_servicing,
            "windows_update": windows_update,
            "pending_file_rename": pending_file_rename,
        },
    }
    if count is not None:
        detail["pending_file_rename_count"] = count
    return detail


def test_reboot_cause_needs_either_sources_or_an_inventory_snapshot() -> None:
    assert monitoring.REBOOT_CAUSE_LOOKBACK == timedelta(days=7)
    assert monitoring.derive_reboot_cause(None, None, NOW - timedelta(days=7)) is None
    assert (
        monitoring.derive_reboot_cause(
            None, {"reason": "reboot_pending"}, NOW - timedelta(days=7)
        )
        is None
    )

    # The verdict is a property of the endpoint's registry state, so reported
    # sources stand on their own even with no update inventory to correlate.
    cause = monitoring.derive_reboot_cause(
        None, _detail(windows_update=True), NOW - timedelta(days=7)
    )
    assert cause is not None
    assert cause.verdict == monitoring.REBOOT_CAUSE_UPDATE
    assert cause.snapshot_received_at is None
    assert cause.reboot_flagged_updates == []
    assert cause.recent_installs == []


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

    # A missing sources object must not manufacture a categorical
    # "not update-related" answer for an agent that predates source reporting.
    assert result.sources is None
    assert result.verdict == monitoring.REBOOT_CAUSE_UNKNOWN
    assert set(asdict(result)) == {
        "reboot_flagged_updates",
        "recent_installs",
        "system_reboot_required",
        "scanned_at",
        "snapshot_received_at",
        "sources",
        "verdict",
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


def test_each_source_alone_yields_its_own_categorical_verdict(monkeypatch) -> None:
    monkeypatch.setattr(monitoring, "_now", lambda: NOW)
    snapshot = _snapshot(
        {"scanned_at": None, "reboot_required": True, "missing": [], "installed": []}
    )
    cases = [
        (_detail(windows_update=True), monitoring.REBOOT_CAUSE_UPDATE),
        (
            _detail(pending_file_rename=True, count=3),
            monitoring.REBOOT_CAUSE_NOT_UPDATE,
        ),
        (
            _detail(component_based_servicing=True),
            monitoring.REBOOT_CAUSE_NOT_UPDATE,
        ),
        (
            _detail(
                component_based_servicing=True,
                windows_update=True,
                pending_file_rename=True,
                count=1,
            ),
            monitoring.REBOOT_CAUSE_UPDATE,
        ),
        # Nothing set is contradictory for a pending alert; never read it as a
        # negative answer.
        (_detail(), monitoring.REBOOT_CAUSE_UNKNOWN),
    ]
    for detail, expected in cases:
        cause = monitoring.derive_reboot_cause(
            snapshot, detail, NOW - monitoring.REBOOT_CAUSE_LOOKBACK
        )
        assert cause is not None
        assert cause.verdict == expected, detail
        assert cause.sources is not None
        assert (
            cause.sources.windows_update is detail["sources"]["windows_update"]
        )


def test_absent_or_malformed_sources_stay_unknown(monkeypatch) -> None:
    monkeypatch.setattr(monitoring, "_now", lambda: NOW)
    snapshot = _snapshot(
        {"scanned_at": None, "reboot_required": True, "missing": [], "installed": []}
    )
    for detail in [
        None,
        {},
        {"reason": "reboot_pending"},
        {"sources": None},
        {"sources": "true"},
        {"sources": {"windows_update": True}},  # incomplete
        {
            "sources": {
                "component_based_servicing": False,
                "windows_update": "true",  # not a boolean
                "pending_file_rename": False,
            }
        },
    ]:
        cause = monitoring.derive_reboot_cause(
            snapshot, detail, NOW - monitoring.REBOOT_CAUSE_LOOKBACK
        )
        assert cause is not None
        assert cause.sources is None, detail
        assert cause.verdict == monitoring.REBOOT_CAUSE_UNKNOWN, detail


def test_file_rename_count_is_best_effort_and_never_a_path(monkeypatch) -> None:
    monkeypatch.setattr(monitoring, "_now", lambda: NOW)
    snapshot = _snapshot(
        {"scanned_at": None, "reboot_required": True, "missing": [], "installed": []}
    )

    counted = monitoring.derive_reboot_cause(
        snapshot,
        _detail(pending_file_rename=True, count=4),
        NOW - monitoring.REBOOT_CAUSE_LOOKBACK,
    )
    assert counted is not None and counted.sources is not None
    assert counted.sources.pending_file_rename_count == 4

    # A missing, negative, non-integer, or boolean count degrades to unknown
    # without disturbing the verdict the presence flags already decided.
    for bad in [None, -1, True, "12", 2.5, [r"C:\Users\alice\tmp"]]:
        cause = monitoring.derive_reboot_cause(
            snapshot,
            _detail(pending_file_rename=True, count=bad),
            NOW - monitoring.REBOOT_CAUSE_LOOKBACK,
        )
        assert cause is not None and cause.sources is not None
        assert cause.sources.pending_file_rename_count is None, bad
        assert cause.verdict == monitoring.REBOOT_CAUSE_NOT_UPDATE

    # The rendered payload carries the flags and a count, and nothing else --
    # in particular no field that could hold a file path.
    payload = RebootCauseOut.model_validate(counted).model_dump()
    assert set(payload["sources"]) == {
        "component_based_servicing",
        "windows_update",
        "pending_file_rename",
        "pending_file_rename_count",
    }
    assert payload["verdict"] == monitoring.REBOOT_CAUSE_NOT_UPDATE


def test_reboot_verdict_values_match_the_published_contract() -> None:
    assert monitoring.REBOOT_CAUSE_UPDATE == "update_caused"
    assert monitoring.REBOOT_CAUSE_NOT_UPDATE == "not_update_caused"
    assert monitoring.REBOOT_CAUSE_UNKNOWN == "unknown"
    assert RebootCauseOut.model_fields["verdict"].default == "unknown"
    assert RebootCauseOut.model_fields["sources"].default is None


def test_source_detail_stays_within_the_bounded_result_limit() -> None:
    """The added keys are a fixed, tiny cost against the 16 KiB detail cap."""
    detail = _detail(
        component_based_servicing=True,
        windows_update=True,
        pending_file_rename=True,
        count=2**31,
    )
    detail["raw_status"] = "critical"
    detail["hysteresis"] = {"pending_status": "", "pending_count": 0}
    encoded = json.dumps(detail, separators=(",", ":")).encode("utf-8")
    assert len(encoded) < 512
    assert AgentCheckResultIn.model_validate(
        {
            "id": "0" * 32,
            "policy_id": "policy-1",
            "policy_revision_id": "revision-1",
            "check_key": "reboot",
            "status": "critical",
            "value": 1.0,
            "detail": detail,
            "evaluated_at": NOW,
        }
    ).detail == detail
