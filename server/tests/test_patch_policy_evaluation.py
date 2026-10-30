# SPDX-License-Identifier: AGPL-3.0-only
"""Direct table tests for patch rule parsing and evaluation (issue #285).

``test_patch_policies.py`` covers the HTTP surface and the install gate; this
file calls ``parse_rules`` and ``evaluate_update`` directly with no database.
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_patch_policy_evaluation.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

from datetime import datetime, timedelta, timezone  # noqa: E402

import pytest  # noqa: E402
from pydantic import ValidationError  # noqa: E402

from app.core.patch_policies import (  # noqa: E402
    UpdateDecision,
    evaluate_update,
    parse_rules,
)

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def _rule(key, action, defer_days=None, **match):
    raw = {"key": key, "action": action, "match": match}
    if defer_days is not None:
        raw["defer_days"] = defer_days
    return raw


# --------------------------------------------------------------------------- #
# parse_rules
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("raw", [None, []])
def test_parse_rules_empty(raw):
    assert parse_rules(raw) == []


def test_parse_rules_normalizes_and_keeps_order():
    rules = parse_rules(
        [
            _rule("first", "deny", kb_ids=[" kb1234567 ", "KB1234567"]),
            _rule("second", "defer", defer_days=7, severities=["Critical"]),
        ]
    )
    assert [rule.key for rule in rules] == ["first", "second"]
    assert rules[0].match.kb_ids == ["KB1234567"]
    assert rules[1].defer_days == 7


@pytest.mark.parametrize(
    "bad",
    [
        _rule("no-facet", "approve"),
        _rule("defer-missing-days", "defer", classifications=["Security Updates"]),
        _rule("days-on-approve", "approve", defer_days=3, classifications=["x"]),
        _rule("bad-kb", "deny", kb_ids=["123"]),
        _rule("Bad Key", "deny", severities=["Critical"]),
        {**_rule("extra", "deny", severities=["Critical"]), "unexpected": 1},
        _rule("bad-action", "maybe", severities=["Critical"]),
    ],
)
def test_parse_rules_rejects_hand_edited_rows(bad):
    with pytest.raises(ValidationError):
        parse_rules([bad])


# --------------------------------------------------------------------------- #
# evaluate_update
# --------------------------------------------------------------------------- #
CRITICAL_SECURITY = {
    "kb_id": "KB5000001",
    "classification": "Security Updates",
    "severity": "Critical",
    "last_deployment_change": "2026-05-01T00:00:00Z",
}


@pytest.mark.parametrize(
    "default_action,expected",
    [("approve", "approve"), ("deny", "deny"), ("anything-else", "deny")],
)
def test_no_rules_falls_back_to_default(default_action, expected):
    assert evaluate_update([], default_action, CRITICAL_SECURITY, NOW) == UpdateDecision(
        expected, "default", None
    )


@pytest.mark.parametrize(
    "match,update,matches",
    [
        # Facet matching is case-insensitive and whitespace-tolerant.
        ({"classifications": ["security updates"]}, {"classification": " Security Updates "}, True),
        ({"classifications": ["Drivers"]}, {"classification": "Security Updates"}, False),
        # A constrained facet never matches an update that lacks that field.
        ({"severities": ["Critical"]}, {"classification": "x"}, False),
        ({"severities": ["Critical", "Important"]}, {"severity": "important"}, True),
        # KB ids compare upper-cased; missing/empty kb_id never matches.
        ({"kb_ids": ["KB5000001"]}, {"kb_id": " kb5000001"}, True),
        ({"kb_ids": ["KB5000001"]}, {"kb_id": "KB5000002"}, False),
        ({"kb_ids": ["KB5000001"]}, {"kb_id": ""}, False),
        ({"kb_ids": ["KB5000001"]}, {}, False),
        # Facets within a rule are ANDed.
        (
            {"classifications": ["Security Updates"], "severities": ["Low"]},
            {"classification": "Security Updates", "severity": "Critical"},
            False,
        ),
        (
            {"classifications": ["Security Updates"], "severities": ["Critical"], "kb_ids": ["KB5000001"]},
            CRITICAL_SECURITY,
            True,
        ),
    ],
)
def test_rule_facet_matching(match, update, matches):
    rules = parse_rules([_rule("r", "approve", **match)])
    decision = evaluate_update(rules, "deny", update, NOW)
    if matches:
        assert decision == UpdateDecision("approve", "rule:r", "r")
    else:
        assert decision == UpdateDecision("deny", "default", None)


@pytest.mark.parametrize(
    "action,expected",
    [("approve", "approve"), ("deny", "deny")],
)
def test_approve_and_deny_rules(action, expected):
    rules = parse_rules([_rule("r", action, severities=["Critical"])])
    default = "deny" if action == "approve" else "approve"
    assert evaluate_update(rules, default, CRITICAL_SECURITY, NOW) == UpdateDecision(
        expected, "rule:r", "r"
    )


def test_first_match_wins():
    rules = parse_rules(
        [
            _rule("skip", "approve", classifications=["Drivers"]),
            _rule("deny-kb", "deny", kb_ids=["KB5000001"]),
            _rule("approve-critical", "approve", severities=["Critical"]),
        ]
    )
    assert evaluate_update(rules, "approve", CRITICAL_SECURITY, NOW) == UpdateDecision(
        "deny", "rule:deny-kb", "deny-kb"
    )


@pytest.mark.parametrize(
    "released,expected",
    [
        # Released 31 days before NOW: a 30-day deferral has elapsed.
        ("2026-05-01T12:00:00Z", "approve"),
        # Exactly at the boundary counts as elapsed.
        ("2026-05-02T12:00:00+00:00", "approve"),
        ("2026-05-02T12:00:01+00:00", "defer"),
        # Naive ISO strings are read as UTC.
        ("2026-05-02T12:00:00", "approve"),
        (datetime(2026, 5, 1, tzinfo=timezone.utc), "approve"),
        (datetime(2026, 5, 1), "approve"),
        (datetime(2026, 5, 30, tzinfo=timezone.utc), "defer"),
        # Unknown or unparseable age fails closed: stays deferred.
        (None, "defer"),
        ("not-a-date", "defer"),
        (12345, "defer"),
    ],
)
def test_defer_rule(released, expected):
    rules = parse_rules([_rule("hold", "defer", defer_days=30, severities=["Critical"])])
    update = {"severity": "Critical", "last_deployment_change": released}
    decision = evaluate_update(rules, "approve", update, NOW)
    if expected == "approve":
        assert decision == UpdateDecision("approve", "rule:hold:deferral_elapsed", "hold")
    else:
        assert decision == UpdateDecision("defer", "rule:hold:deferred", "hold")


def test_defer_rule_missing_release_field_stays_deferred():
    rules = parse_rules([_rule("hold", "defer", defer_days=1, severities=["Critical"])])
    assert evaluate_update(rules, "approve", {"severity": "Critical"}, NOW).decision == "defer"


def test_now_defaults_to_current_time():
    rules = parse_rules([_rule("hold", "defer", defer_days=1, severities=["Critical"])])
    recent = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    old = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    assert evaluate_update(rules, "deny", {"severity": "Critical", "last_deployment_change": recent}).decision == "defer"
    assert evaluate_update(rules, "deny", {"severity": "Critical", "last_deployment_change": old}).decision == "approve"
