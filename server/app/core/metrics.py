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
            "# HELP nodelink_monitoring_operations_total Monitoring result and evaluation counters.",
            "# TYPE nodelink_monitoring_operations_total counter",
        )
    )
    for name in (
        "monitoring_result_accepted_total",
        "monitoring_result_duplicate_total",
        "monitoring_result_rejected_total",
        "monitoring_offline_evaluation_total",
        "monitoring_alert_opened_total",
        "monitoring_alert_occurrence_total",
        "monitoring_alert_recovered_total",
        "monitoring_alert_reopened_total",
        "monitoring_alert_suppressed_occurrence_total",
        "monitoring_alert_out_of_order_total",
        "monitoring_alert_policy_change_total",
        "monitoring_alert_policy_superseded_total",
        "monitoring_alert_duplicate_observation_total",
    ):
        operation = name.removeprefix("monitoring_").removesuffix("_total")
        lines.append(
            f'nodelink_monitoring_operations_total{{operation="{operation}"}} '
            f"{values.get(name, 0)}"
        )
    lines.extend(
        (
            "# HELP nodelink_alert_email_operations_total Alert email queue and delivery counters.",
            "# TYPE nodelink_alert_email_operations_total counter",
        )
    )
    for name in (
        "email_alert_queued_total",
        "email_alert_sent_total",
        "email_alert_retrying_total",
        "email_alert_failed_total",
        "email_alert_manual_retry_total",
        "email_alert_claim_recovered_total",
        "email_alert_configuration_error_total",
        "email_alert_suppressed_total",
    ):
        operation = name.removeprefix("email_alert_").removesuffix("_total")
        lines.append(
            f'nodelink_alert_email_operations_total{{operation="{operation}"}} '
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
