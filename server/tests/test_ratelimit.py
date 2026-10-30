# SPDX-License-Identifier: AGPL-3.0-only
"""Direct unit tests for ``app.core.ratelimit`` (issue #285).

Time is driven through a fake ``time.monotonic`` so window expiry is exact.
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_ratelimit.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import pytest  # noqa: E402

from app.core import ratelimit  # noqa: E402
from app.core.ratelimit import LoginRateLimiter  # noqa: E402


class Clock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch):
    fake = Clock()
    monkeypatch.setattr(ratelimit.time, "monotonic", fake)
    return fake


def test_not_blocked_below_threshold(clock):
    limiter = LoginRateLimiter(max_failures=3, window_seconds=60)
    assert limiter.retry_after("k") is None
    limiter.record_failure("k")
    limiter.record_failure("k")
    assert limiter.retry_after("k") is None


def test_blocked_at_threshold_with_retry_after(clock):
    limiter = LoginRateLimiter(max_failures=3, window_seconds=60)
    for step in range(3):
        clock.now = 1000.0 + step * 10
        limiter.record_failure("k")
    clock.now = 1025.0
    # Oldest failure at t=1000 ages out at t=1060.
    assert limiter.retry_after("k") == pytest.approx(35.0)


def test_window_expiry_unblocks_and_drops_key(clock):
    limiter = LoginRateLimiter(max_failures=2, window_seconds=60)
    limiter.record_failure("k")
    limiter.record_failure("k")
    assert limiter.retry_after("k") is not None
    # At exactly cutoff the entry is pruned (<= cutoff).
    clock.now = 1060.0
    assert limiter.retry_after("k") is None
    assert "k" not in limiter._failures


def test_sliding_window_prunes_only_old_entries(clock):
    limiter = LoginRateLimiter(max_failures=2, window_seconds=60)
    limiter.record_failure("k")  # t=1000
    clock.now = 1050.0
    limiter.record_failure("k")  # t=1050
    assert limiter.retry_after("k") == pytest.approx(10.0)
    clock.now = 1061.0
    assert limiter.retry_after("k") is None
    assert len(limiter._failures["k"]) == 1


def test_retry_after_never_negative(clock):
    limiter = LoginRateLimiter(max_failures=1, window_seconds=0)
    limiter.record_failure("k")
    # With a zero window the entry is already at the cutoff and pruned.
    assert limiter.retry_after("k") is None


def test_keys_are_independent_and_clear_is_per_key(clock):
    limiter = LoginRateLimiter(max_failures=1, window_seconds=60)
    limiter.record_failure("a")
    limiter.record_failure("b")
    assert limiter.retry_after("a") is not None
    assert limiter.retry_after("b") is not None
    limiter.clear("a")
    assert limiter.retry_after("a") is None
    assert limiter.retry_after("b") is not None
    # Clearing an unknown key is a no-op.
    limiter.clear("never-seen")


def test_reset_drops_all_state(clock):
    limiter = LoginRateLimiter(max_failures=1, window_seconds=60)
    limiter.record_failure("a")
    limiter.record_failure("b")
    limiter.reset()
    assert limiter._failures == {}
    assert limiter.retry_after("a") is None


def test_unblocked_lookup_does_not_leave_empty_keys(clock):
    limiter = LoginRateLimiter(max_failures=3, window_seconds=60)
    for key in ("x", "y", "z"):
        assert limiter.retry_after(key) is None
    assert limiter._failures == {}
