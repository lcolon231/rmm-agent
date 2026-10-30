# SPDX-License-Identifier: AGPL-3.0-only
"""Direct unit tests for patch compliance aggregation helpers (issue #285).

``test_patch_compliance.py`` covers the HTTP surface. This file tests
``summarize`` and the pure snapshot helpers it depends on, with no database.
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_patch_compliance_summary.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

from datetime import datetime, timedelta, timezone  # noqa: E402

import pytest  # noqa: E402

from app.core import patch_compliance as pc  # noqa: E402
from app.core.patch_policies import parse_rules  # noqa: E402
from app.models.models import AgentInventorySnapshot  # noqa: E402

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def _row(state: str, approved: int = 0) -> pc.EndpointCompliance:
    return pc.EndpointCompliance(
        agent_id=f"a-{state}-{approved}",
        hostname="host",
        site_id="s",
        site_name="Site",
        client_id="c",
        client_name="Client",
        state=state,
        policy_id=None if state == pc.STATE_EXEMPT else "p",
        scanned_at=None,
        total_missing=approved,
        approved_missing=approved,
        deferred_missing=0,
        denied_missing=0,
    )


# --------------------------------------------------------------------------- #
# summarize
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("truncated", [False, True])
def test_summarize_empty(truncated):
    assert pc.summarize([], truncated=truncated) == pc.ComplianceSummary(
        total_endpoints=0, compliant=0, non_compliant=0, stale=0, unknown=0,
        exempt=0, total_approved_missing=0, truncated=truncated,
    )


def test_summarize_counts_each_state_and_sums_approved_missing():
    rows = [
        _row(pc.STATE_COMPLIANT),
        _row(pc.STATE_COMPLIANT),
        _row(pc.STATE_NON_COMPLIANT, approved=3),
        _row(pc.STATE_NON_COMPLIANT, approved=1),
        _row(pc.STATE_STALE, approved=2),
        _row(pc.STATE_UNKNOWN),
        _row(pc.STATE_EXEMPT),
    ]
    assert pc.summarize(rows, truncated=True) == pc.ComplianceSummary(
        total_endpoints=7,
        compliant=2,
        non_compliant=2,
        stale=1,
        unknown=1,
        exempt=1,
        # Stale rows still contribute what their last scan showed.
        total_approved_missing=6,
        truncated=True,
    )


@pytest.mark.parametrize("state", pc.COMPLIANCE_STATES)
def test_summarize_single_state(state):
    summary = pc.summarize([_row(state)], truncated=False)
    assert summary.total_endpoints == 1
    counted = {
        pc.STATE_COMPLIANT: summary.compliant,
        pc.STATE_NON_COMPLIANT: summary.non_compliant,
        pc.STATE_STALE: summary.stale,
        pc.STATE_UNKNOWN: summary.unknown,
        pc.STATE_EXEMPT: summary.exempt,
    }
    assert counted[state] == 1
    assert sum(counted.values()) == 1


def test_summarize_rejects_unknown_state():
    with pytest.raises(KeyError):
        pc.summarize([_row("bogus")], truncated=False)


# --------------------------------------------------------------------------- #
# Snapshot helpers
# --------------------------------------------------------------------------- #
def _snapshot(status="ok", payload=None, collected_at=None) -> AgentInventorySnapshot:
    return AgentInventorySnapshot(
        agent_id="a", section="windows_updates", status=status,
        payload=payload, collected_at=collected_at,
    )


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, None),
        ("2026-05-01T00:00:00Z", datetime(2026, 5, 1, tzinfo=timezone.utc)),
        ("2026-05-01T00:00:00", datetime(2026, 5, 1, tzinfo=timezone.utc)),
        (datetime(2026, 5, 1), datetime(2026, 5, 1, tzinfo=timezone.utc)),
        ("garbage", None),
        (17, None),
    ],
)
def test_parse_dt(value, expected):
    assert pc._parse_dt(value) == expected


def test_scan_datetime_prefers_payload_then_collected_at():
    assert pc._scan_datetime(None) is None
    collected = datetime(2026, 4, 1)
    assert pc._scan_datetime(
        _snapshot(payload={"scanned_at": "2026-05-01T00:00:00Z"}, collected_at=collected)
    ) == datetime(2026, 5, 1, tzinfo=timezone.utc)
    assert pc._scan_datetime(
        _snapshot(payload={"scanned_at": "bad"}, collected_at=collected)
    ) == datetime(2026, 4, 1, tzinfo=timezone.utc)
    assert pc._scan_datetime(_snapshot(payload=None)) is None


@pytest.mark.parametrize(
    "status,payload,usable",
    [
        ("ok", {}, True),
        ("partial", {"missing": []}, True),
        ("ok", None, True),
        ("error", {}, False),
        ("unsupported", {}, False),
        ("ok", {"error_code": "wua_unavailable"}, False),
    ],
)
def test_usable(status, payload, usable):
    assert pc._usable(_snapshot(status=status, payload=payload)) is usable


@pytest.mark.parametrize(
    "payload,expected",
    [
        (None, []),
        ({}, []),
        ({"missing": "nope"}, []),
        ({"missing": [{"kb_id": "KB1"}, "junk", 3, {"kb_id": "KB2"}]}, [{"kb_id": "KB1"}, {"kb_id": "KB2"}]),
    ],
)
def test_missing_rows_keeps_only_dicts(payload, expected):
    assert pc._missing_rows(_snapshot(payload=payload)) == expected


def test_tally_splits_by_decision():
    rules = parse_rules(
        [
            {"key": "deny-low", "action": "deny", "match": {"severities": ["Low"]}},
            {"key": "hold", "action": "defer", "defer_days": 30, "match": {"severities": ["Important"]}},
            {"key": "ok", "action": "approve", "match": {"severities": ["Critical"]}},
        ]
    )
    recent = (NOW - timedelta(days=1)).isoformat()
    missing = [
        {"severity": "Critical"},
        {"severity": "Critical"},
        {"severity": "Important", "last_deployment_change": recent},
        {"severity": "Low"},
        {"severity": "Moderate"},  # default deny
    ]
    assert pc._tally(rules, "deny", missing, NOW) == (2, 1, 2)
