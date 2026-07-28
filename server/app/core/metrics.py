# SPDX-License-Identifier: AGPL-3.0-only
"""Small dependency-free process metrics for enrollment operations.

These counters are intentionally process-local. They support a single-worker
pilot and health verification; production HA requires a metrics collector that
aggregates all workers.
"""
from __future__ import annotations

from collections import Counter
from threading import Lock


_lock = Lock()
_counters: Counter[str] = Counter()


def increment(name: str, amount: int = 1) -> None:
    with _lock:
        _counters[name] += amount


def snapshot() -> dict[str, int]:
    with _lock:
        return dict(_counters)


def prometheus_text(agent_statuses: dict[str, int] | None = None) -> str:
    values = snapshot()
    names = (
        "enrollment_success_total",
        "enrollment_failure_total",
        "enrollment_token_created_total",
        "enrollment_token_revoked_total",
        "agent_credential_renewed_total",
        "agent_revoked_total",
    )
    lines = [
        "# HELP nodelink_enrollment_operations_total NodeLink enrollment operation counters.",
        "# TYPE nodelink_enrollment_operations_total counter",
    ]
    for name in names:
        operation = name.removesuffix("_total")
        lines.append(
            f'nodelink_enrollment_operations_total{{operation="{operation}"}} '
            f"{values.get(name, 0)}"
        )
    lines.extend(
        (
            "# HELP nodelink_agents Current agents by operational status.",
            "# TYPE nodelink_agents gauge",
        )
    )
    for status, count in sorted((agent_statuses or {}).items()):
        safe_status = status.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'nodelink_agents{{status="{safe_status}"}} {count}')
    return "\n".join(lines) + "\n"
