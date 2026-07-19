# SPDX-License-Identifier: AGPL-3.0-only
"""Fast smoke test of the soak harness (issue #77).

Runs the harness for a few seconds against the in-process app so the workload,
fault injection, sampling, integrity checks, and report generation are all
verified in CI — without the multi-day duration a real soak needs. It asserts:
  - the workload actually flowed (enrolled, dispatched, picked up, completed)
  - audit integrity held throughout and the summary says so
  - evidence, summary, and report files are written and well-formed
  - an outage was injected and recovered

Run just this file:  pytest tests/test_soak_harness.py -q
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_soak.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402

from app.main import app  # noqa: E402
from app.core.database import Base, engine, AsyncSessionLocal  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.models.models import Operator, OperatorRole  # noqa: E402

# Load the harness module by path (it lives under deploy/, outside the package).
_SOAK_PATH = Path(__file__).resolve().parents[2] / "deploy" / "soak" / "soak.py"
_spec = importlib.util.spec_from_file_location("nodelink_soak", _SOAK_PATH)
soak = importlib.util.module_from_spec(_spec)
# Register before exec so dataclasses can resolve the module's namespace.
sys.modules["nodelink_soak"] = soak
_spec.loader.exec_module(soak)


@pytest_asyncio.fixture
async def app_client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add(Operator(email="soak@nodelink.test", password_hash=hash_password("pw"),
                        role=OperatorRole.admin))
        await db.commit()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        yield c
    await engine.dispose()


@pytest.mark.asyncio
async def test_soak_harness_smoke(app_client, tmp_path):
    cfg = soak.SoakConfig(
        admin_email="soak@nodelink.test",
        admin_password="pw",
        duration_seconds=3.0,
        agents=3,
        heartbeat_interval=0.5,
        dispatch_interval=0.5,
        sample_interval=0.5,
        outage_every=1.0,
        outage_duration=0.5,
        evidence_dir=str(tmp_path / "evidence"),
    )
    # No server PID in-process; sampling returns {} and the report notes it.
    summary = await soak.run_soak(app_client, cfg, sampler=soak.ProcSampler(None))

    assert summary["passed"] is True, summary["critical_findings"]
    assert summary["audit_intact_throughout"] is True
    c = summary["counters"]
    assert c["dispatched"] > 0
    assert c["picked_up"] > 0
    assert c["results_ok"] > 0
    assert c["heartbeats_ok"] > 0
    assert summary["outages_injected"] >= 1
    # Harness counting invariant (deterministic): every picked-up command is
    # accounted for as exactly one OK or error result. The success *rate* itself
    # is environment-dependent (this smoke runs on SQLite, which serializes
    # concurrent writers); the meaningful rate is measured in the real run
    # against PostgreSQL.
    assert c["results_ok"] + c["results_err"] == c["picked_up"]

    # Evidence artifacts exist and are well-formed.
    d = tmp_path / "evidence"
    assert (d / "soak-evidence.jsonl").read_text().strip(), "no evidence lines"
    import json
    written = json.loads((d / "soak-summary.json").read_text())
    assert written["passed"] is True
    report = (d / "soak-report.md").read_text()
    assert "Result: PASS" in report
    assert "Audit chain intact at every sample: True" in report


@pytest.mark.asyncio
async def test_soak_reports_provisioning_failure(app_client, tmp_path):
    # Wrong password -> provisioning fails -> a CRITICAL finding, non-passing.
    cfg = soak.SoakConfig(
        admin_email="soak@nodelink.test", admin_password="wrong",
        duration_seconds=1.0, agents=2, evidence_dir=str(tmp_path / "ev"),
    )
    summary = await soak.run_soak(app_client, cfg, sampler=soak.ProcSampler(None))
    assert summary["passed"] is False
    assert any("provisioning failed" in f for f in summary["critical_findings"])
