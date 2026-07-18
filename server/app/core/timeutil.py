# SPDX-License-Identifier: AGPL-3.0-only
"""Datetime helpers.

SQLite returns naive datetimes even for TIMESTAMP columns, while PostgreSQL
(with DateTime(timezone=True)) returns tz-aware ones. To keep comparison logic
correct across both, always pass values read back from the DB through
``ensure_utc`` before comparing them with ``now()``.
"""
from __future__ import annotations

from datetime import datetime, timezone


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def ensure_utc(dt: datetime | None) -> datetime | None:
    """Return a tz-aware UTC datetime. Naive inputs are assumed to be UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
