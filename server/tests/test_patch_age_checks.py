# SPDX-License-Identifier: AGPL-3.0-only
"""Patch-age monitoring policy and evaluator behavior (issue #229)."""
from __future__ import annotations

import os

import pytest
from pydantic import ValidationError

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_patch_age_checks.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

from app.schemas.monitoring import MonitoringPolicyCreate  # noqa: E402


def _check(
    *,
    check_type: str = "patch_age",
    op: str = "gt",
    interval_seconds: int = 3600,
    params: dict | None = None,
) -> dict:
    return {
        "key": "patch-age",
        "type": check_type,
        "enabled": True,
        "schedule": {"interval_seconds": interval_seconds},
        "threshold": {"op": op, "warning": 30, "critical": 60},
        "params": params or {},
    }


def _policy(check: dict) -> dict:
    return {
        "name": "Patch age",
        "scope": "global",
        "scope_id": None,
        "checks": [check],
    }


def test_patch_age_accepts_rising_threshold_without_params():
    policy = MonitoringPolicyCreate.model_validate(_policy(_check()))

    assert policy.checks[0].type.value == "patch_age"
    assert policy.checks[0].schedule.interval_seconds == 3600


@pytest.mark.parametrize("op", ["lt", "lte"])
def test_patch_age_rejects_falling_thresholds(op: str):
    with pytest.raises(ValidationError, match="rising threshold"):
        MonitoringPolicyCreate.model_validate(_policy(_check(op=op)))


def test_patch_age_rejects_params():
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        MonitoringPolicyCreate.model_validate(
            _policy(_check(params={"source": "windows_updates"}))
        )


def test_patch_age_has_a_type_specific_hourly_cadence_floor():
    with pytest.raises(ValidationError, match="at least 3600 seconds"):
        MonitoringPolicyCreate.model_validate(
            _policy(_check(interval_seconds=3599))
        )

    cpu = _check(check_type="cpu", interval_seconds=30)
    cpu["key"] = "cpu"
    MonitoringPolicyCreate.model_validate(_policy(cpu))
