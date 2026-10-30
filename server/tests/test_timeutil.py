# SPDX-License-Identifier: AGPL-3.0-only
"""Direct unit tests for ``app.core.timeutil`` (issue #285)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.core.timeutil import ensure_utc, now_utc


def test_now_utc_is_aware_utc():
    before = datetime.now(timezone.utc)
    value = now_utc()
    after = datetime.now(timezone.utc)
    assert value.tzinfo is timezone.utc
    assert before <= value <= after


def test_ensure_utc_none_passes_through():
    assert ensure_utc(None) is None


def test_ensure_utc_naive_is_assumed_utc():
    naive = datetime(2026, 1, 2, 3, 4, 5)
    result = ensure_utc(naive)
    assert result == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert result.tzinfo is timezone.utc


def test_ensure_utc_converts_other_offsets():
    plus_five = timezone(timedelta(hours=5))
    result = ensure_utc(datetime(2026, 1, 2, 8, 0, tzinfo=plus_five))
    assert result == datetime(2026, 1, 2, 3, 0, tzinfo=timezone.utc)
    assert result.tzinfo is timezone.utc
    assert result.hour == 3


def test_ensure_utc_aware_utc_unchanged():
    value = datetime(2026, 1, 2, tzinfo=timezone.utc)
    assert ensure_utc(value) == value


def test_ensure_utc_makes_db_values_comparable_with_now():
    # The reason the helper exists: SQLite hands back naive datetimes, which
    # cannot be compared with now_utc() directly.
    naive_past = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=1)
    assert ensure_utc(naive_past) < now_utc()
