# SPDX-License-Identifier: AGPL-3.0-only
"""In-process sliding-window rate limiting for login attempts.

Counts *failed* logins per (client IP, email) and blocks further attempts for
that pair once the window fills, slowing online password brute-force without
letting an attacker lock a victim out from a different address.

Scope and honesty notes:

- State lives in this process. Behind multiple uvicorn workers each worker
  enforces its own window, so the effective global limit is multiplied by the
  worker count. Good enough to blunt brute force on a scaffold; move the
  counters to a shared store (e.g. Redis) before scaling out.
- Successful login clears the pair's counter, so a legitimate user who fat-
  fingers a password a few times is not penalized after they get it right.
"""
from __future__ import annotations

import time
from collections import deque

from app.core.config import settings


class LoginRateLimiter:
    """Sliding-window failure counter keyed by an opaque string."""

    def __init__(self, max_failures: int, window_seconds: float) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self._failures: dict[str, deque[float]] = {}

    def _prune(self, key: str, now: float) -> deque[float]:
        q = self._failures.setdefault(key, deque())
        cutoff = now - self.window_seconds
        while q and q[0] <= cutoff:
            q.popleft()
        if not q:
            # Don't let abandoned keys accumulate forever.
            self._failures.pop(key, None)
        return q

    def retry_after(self, key: str) -> float | None:
        """Seconds until `key` may try again, or None if it is not blocked."""
        now = time.monotonic()
        q = self._prune(key, now)
        if len(q) < self.max_failures:
            return None
        return max(0.0, q[0] + self.window_seconds - now)

    def record_failure(self, key: str) -> None:
        now = time.monotonic()
        self._prune(key, now)
        self._failures.setdefault(key, deque()).append(now)

    def clear(self, key: str) -> None:
        self._failures.pop(key, None)

    def reset(self) -> None:
        """Drop all state (test isolation)."""
        self._failures.clear()


# Module-level singleton, mirroring how `settings` is exposed.
login_limiter = LoginRateLimiter(
    max_failures=settings.login_max_failures,
    window_seconds=settings.login_window_seconds,
)
