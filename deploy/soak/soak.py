# SPDX-License-Identifier: AGPL-3.0-only
"""NodeLink soak-test harness (issue #77).

Drives a running NodeLink deployment with a sustained, realistic workload while
sampling resource and integrity signals, so a multi-day run produces objective
evidence of stability. It exercises the endurance-relevant server paths:
enrollment, heartbeat/poll, command dispatch under admission control, buffered
result submission, agent outage + recovery, and continuous audit-chain +
external-anchor verification.

What it records, as newline-delimited JSON (`soak-evidence.jsonl`) plus a
human-readable `soak-report.md` and machine `soak-summary.json`:

  - server process RSS and open file descriptors over time (leak detection),
    when a server PID is available
  - command throughput and outcomes (dispatched, succeeded, failed, and
    admission-rejected 429s)
  - audit chain integrity at every sample (a single break is a CRITICAL finding)
  - external anchor publication lag/health at every sample
  - injected agent outages and whether each agent recovered afterward

Pass/fail: the run exits non-zero if any CRITICAL finding is recorded (audit
chain broke, or the workload could not run), so it doubles as a gate. Warnings
(e.g. RSS growth, publication lag) are reported but do not fail the run — a
human judges them against the documented thresholds in docs/SOAK-TEST.md.

This harness produces the evidence; the multi-day *duration* is the operator's
to run. See docs/SOAK-TEST.md.

Usage (against a running server on the default local port):

    python deploy/soak/soak.py \
        --base-url http://127.0.0.1:8000 \
        --admin-email you@example.com --admin-password '...' \
        --duration-seconds 259200 --agents 25 \
        --evidence-dir ./soak-evidence
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import httpx


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
@dataclass
class SoakConfig:
    base_url: str = "http://127.0.0.1:8000"
    api_prefix: str = "/api/v1"
    admin_email: str = ""
    admin_password: str = ""
    duration_seconds: float = 3 * 24 * 3600
    agents: int = 25
    heartbeat_interval: float = 30.0
    dispatch_interval: float = 5.0
    sample_interval: float = 60.0
    # Every `outage_every` seconds, take one agent dark for `outage_duration`
    # seconds, then let it recover. 0 disables outage injection.
    outage_every: float = 900.0
    outage_duration: float = 120.0
    server_pid: int | None = None
    evidence_dir: str = "./soak-evidence"
    # Warning thresholds (not failures): documented in docs/SOAK-TEST.md.
    rss_growth_warn_ratio: float = 1.5
    fd_growth_warn_ratio: float = 1.5


# --------------------------------------------------------------------------- #
# Resource sampling
# --------------------------------------------------------------------------- #
class ProcSampler:
    """Reads RSS and open-FD count for a PID from /proc (Linux). Best-effort:
    returns {} when the PID is unknown or /proc is unavailable (e.g. the server
    runs on another host — sample it there and merge externally)."""

    def __init__(self, pid: int | None):
        self.pid = pid

    def sample(self) -> dict:
        if self.pid is None:
            return {}
        out: dict = {}
        try:
            status = Path(f"/proc/{self.pid}/status").read_text()
            for line in status.splitlines():
                if line.startswith("VmRSS:"):
                    out["rss_kb"] = int(line.split()[1])
                    break
        except OSError:
            return {}
        try:
            out["open_fds"] = len(os.listdir(f"/proc/{self.pid}/fd"))
        except OSError:
            pass
        return out


def autodetect_server_pid() -> int | None:
    """Find a local uvicorn/app.main process. Returns None if not found or not
    on Linux."""
    proc = Path("/proc")
    if not proc.is_dir():
        return None
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes().replace(b"\x00", b" ").decode()
        except OSError:
            continue
        if "uvicorn" in cmdline or "app.main" in cmdline:
            return int(entry.name)
    return None


# --------------------------------------------------------------------------- #
# Shared workload state
# --------------------------------------------------------------------------- #
@dataclass
class Counters:
    dispatched: int = 0
    dispatch_rejected_admission: int = 0
    dispatch_errors: int = 0
    picked_up: int = 0
    results_ok: int = 0
    results_err: int = 0
    heartbeats_ok: int = 0
    heartbeats_err: int = 0


@dataclass
class AgentState:
    agent_id: str
    token: str
    dark_until: float = 0.0  # monotonic time until which this agent is "offline"
    beats_after_recovery: int = 0
    outages: int = 0
    recovered: int = 0


@dataclass
class SoakState:
    counters: Counters = field(default_factory=Counters)
    agents: list[AgentState] = field(default_factory=list)
    samples: list[dict] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)  # outage/recovery markers
    critical: list[str] = field(default_factory=list)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# Workload
# --------------------------------------------------------------------------- #
async def _provision(client: httpx.AsyncClient, cfg: SoakConfig, state: SoakState) -> None:
    """Log in, create a client/site/token, and enroll the simulated agents."""
    r = await client.post(
        f"{cfg.api_prefix}/auth/login",
        json={"email": cfg.admin_email, "password": cfg.admin_password},
    )
    r.raise_for_status()
    client.headers["Authorization"] = f"Bearer {r.json()['access_token']}"

    cl = (await client.post(f"{cfg.api_prefix}/clients", json={"name": "Soak Client"})).json()
    st = (await client.post(f"{cfg.api_prefix}/sites",
                            json={"client_id": cl["id"], "name": "Soak Site"})).json()
    tok = (await client.post(f"{cfg.api_prefix}/enrollment-tokens",
                             json={"site_id": st["id"], "max_uses": cfg.agents + 1})).json()

    for i in range(cfg.agents):
        enr = await client.post(
            f"{cfg.api_prefix}/enroll",
            json={
                "enrollment_token": tok["token"],
                "hostname": f"soak-{i:04d}",
                "os": "windows",
                "supported_command_envelope_versions": ["command-v2"],
            },
        )
        enr.raise_for_status()
        body = enr.json()
        state.agents.append(AgentState(agent_id=body["agent_id"], token=body["agent_token"]))


async def _agent_loop(client: httpx.AsyncClient, cfg: SoakConfig, state: SoakState,
                      agent: AgentState, stop: asyncio.Event) -> None:
    """One simulated agent: heartbeat, pick up commands, submit results, honoring
    injected outage windows."""
    while not stop.is_set():
        if time.monotonic() >= agent.dark_until:
            # If we just came back from an outage, note the recovery once.
            if agent.dark_until and agent.beats_after_recovery == 0:
                state.events.append({"ts": _now_iso(), "agent_id": agent.agent_id,
                                     "event": "recovered"})
            try:
                r = await client.post(
                    f"{cfg.api_prefix}/heartbeat",
                    json={"cpu_percent": random.uniform(1, 40),
                          "mem_percent": random.uniform(20, 70),
                          "supported_command_envelope_versions": ["command-v2"]},
                    headers={"Authorization": f"Bearer {agent.token}"},
                )
                if r.status_code == 200:
                    state.counters.heartbeats_ok += 1
                    if agent.dark_until:
                        agent.beats_after_recovery += 1
                        if agent.beats_after_recovery == 1:
                            agent.recovered += 1
                    for cmd in r.json().get("pending_commands", []):
                        state.counters.picked_up += 1
                        # Result submission has its own error handling so a
                        # failed result is a result error, not a heartbeat one —
                        # results_ok + results_err always equals picked_up.
                        try:
                            res = await client.post(
                                f"{cfg.api_prefix}/commands/{cmd['id']}/result",
                                json={"exit_code": 0, "stdout": "soak-ok"},
                                headers={"Authorization": f"Bearer {agent.token}"},
                            )
                            if res.status_code == 204:
                                state.counters.results_ok += 1
                            else:
                                state.counters.results_err += 1
                        except Exception:
                            state.counters.results_err += 1
                else:
                    state.counters.heartbeats_err += 1
            except Exception:
                state.counters.heartbeats_err += 1
        await _sleep(stop, cfg.heartbeat_interval)


async def _dispatch_loop(client: httpx.AsyncClient, cfg: SoakConfig, state: SoakState,
                         stop: asyncio.Event) -> None:
    while not stop.is_set():
        if state.agents:
            agent = random.choice(state.agents)
            try:
                r = await client.post(
                    f"{cfg.api_prefix}/agents/{agent.agent_id}/commands",
                    json={"kind": "shell", "payload": {"script": "echo soak"}},
                )
                if r.status_code == 200:
                    state.counters.dispatched += 1
                elif r.status_code == 429:
                    state.counters.dispatch_rejected_admission += 1
                else:
                    state.counters.dispatch_errors += 1
            except Exception:
                state.counters.dispatch_errors += 1
        await _sleep(stop, cfg.dispatch_interval)


async def _fault_loop(cfg: SoakConfig, state: SoakState, stop: asyncio.Event) -> None:
    if cfg.outage_every <= 0 or not state.agents:
        return
    while not stop.is_set():
        await _sleep(stop, cfg.outage_every)
        if stop.is_set():
            break
        agent = random.choice(state.agents)
        agent.dark_until = time.monotonic() + cfg.outage_duration
        agent.beats_after_recovery = 0
        agent.outages += 1
        state.events.append({"ts": _now_iso(), "agent_id": agent.agent_id,
                             "event": "outage_start",
                             "duration_seconds": cfg.outage_duration})


async def _sample_loop(client: httpx.AsyncClient, cfg: SoakConfig, state: SoakState,
                       sampler: ProcSampler, evidence_path: Path, start: float,
                       stop: asyncio.Event) -> None:
    while not stop.is_set():
        await _take_sample(client, cfg, state, sampler, evidence_path, start)
        await _sleep(stop, cfg.sample_interval)


async def _take_sample(client: httpx.AsyncClient, cfg: SoakConfig, state: SoakState,
                       sampler: ProcSampler, evidence_path: Path, start: float) -> dict:
    sample: dict = {
        "ts": _now_iso(),
        "elapsed_seconds": round(time.monotonic() - start, 1),
        **sampler.sample(),
        "counters": vars(state.counters).copy(),
    }
    # Audit chain integrity — a break is CRITICAL.
    try:
        av = (await client.get(f"{cfg.api_prefix}/audit/verify")).json()
        sample["audit_intact"] = bool(av.get("intact"))
        if not sample["audit_intact"]:
            msg = f"audit chain broken at {av.get('first_broken_event_id')} (elapsed {sample['elapsed_seconds']}s)"
            if msg not in state.critical:
                state.critical.append(msg)
    except httpx.HTTPError as exc:
        sample["audit_intact"] = None
        sample["audit_error"] = str(exc)
    # External anchor publication health.
    try:
        ps = (await client.get(f"{cfg.api_prefix}/audit/publication-status")).json()
        sample["publication"] = {
            "backend": ps.get("backend"),
            "pending": ps.get("pending"),
            "lag_alert": ps.get("lag_alert"),
        }
    except httpx.HTTPError:
        sample["publication"] = None

    state.samples.append(sample)
    with open(evidence_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(sample, sort_keys=True) + "\n")
    return sample


async def _sleep(stop: asyncio.Event, seconds: float) -> None:
    try:
        await asyncio.wait_for(stop.wait(), timeout=seconds)
    except asyncio.TimeoutError:
        pass


# --------------------------------------------------------------------------- #
# Orchestration + reporting
# --------------------------------------------------------------------------- #
async def run_soak(client: httpx.AsyncClient, cfg: SoakConfig,
                   sampler: ProcSampler | None = None) -> dict:
    """Run the workload for cfg.duration_seconds and return the summary dict.
    Writes evidence/report/summary into cfg.evidence_dir."""
    sampler = sampler or ProcSampler(cfg.server_pid)
    evidence_dir = Path(cfg.evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = evidence_dir / "soak-evidence.jsonl"
    evidence_path.write_text("")  # fresh run

    state = SoakState()
    start = time.monotonic()
    try:
        await _provision(client, cfg, state)
    except httpx.HTTPError as exc:
        state.critical.append(f"provisioning failed: {exc}")
        summary = _summarize(cfg, state, 0.0)
        _write_outputs(cfg, state, summary)
        return summary

    stop = asyncio.Event()
    # One up-front sample as the baseline.
    await _take_sample(client, cfg, state, sampler, evidence_path, start)

    tasks = [
        asyncio.create_task(_dispatch_loop(client, cfg, state, stop)),
        asyncio.create_task(_fault_loop(cfg, state, stop)),
        asyncio.create_task(_sample_loop(client, cfg, state, sampler, evidence_path, start, stop)),
    ]
    tasks += [
        asyncio.create_task(_agent_loop(client, cfg, state, a, stop))
        for a in state.agents
    ]

    try:
        await asyncio.wait_for(stop.wait(), timeout=cfg.duration_seconds)
    except asyncio.TimeoutError:
        pass
    finally:
        stop.set()
        await asyncio.gather(*tasks, return_exceptions=True)

    # Final sample captures the end-state resource/integrity picture.
    await _take_sample(client, cfg, state, sampler, evidence_path, start)
    elapsed = time.monotonic() - start
    summary = _summarize(cfg, state, elapsed)
    _write_outputs(cfg, state, summary)
    return summary


def _summarize(cfg: SoakConfig, state: SoakState, elapsed: float) -> dict:
    c = state.counters
    warnings: list[str] = []

    rss_series = [s["rss_kb"] for s in state.samples if "rss_kb" in s]
    fd_series = [s["open_fds"] for s in state.samples if "open_fds" in s]

    def trend(series):
        if not series:
            return None
        return {"first": series[0], "last": series[-1], "max": max(series),
                "min": min(series), "samples": len(series)}

    rss = trend(rss_series)
    fds = trend(fd_series)
    if rss and rss["first"] > 0 and rss["last"] > rss["first"] * cfg.rss_growth_warn_ratio:
        warnings.append(
            f"RSS grew {rss['first']}->{rss['last']} KiB "
            f"(>{cfg.rss_growth_warn_ratio}x); investigate for a leak")
    if fds and fds["first"] > 0 and fds["last"] > fds["first"] * cfg.fd_growth_warn_ratio:
        warnings.append(
            f"open FDs grew {fds['first']}->{fds['last']} "
            f"(>{cfg.fd_growth_warn_ratio}x); investigate for a descriptor leak")

    audit_samples = [s for s in state.samples if s.get("audit_intact") is not None]
    audit_intact_all = bool(audit_samples) and all(s["audit_intact"] for s in audit_samples)

    outages = sum(a.outages for a in state.agents)
    recovered = sum(a.recovered for a in state.agents)
    if outages and recovered < outages:
        warnings.append(f"{outages - recovered}/{outages} injected outages did not "
                        "show a recovered heartbeat before the run ended")

    lag_samples = [s for s in state.samples
                   if isinstance(s.get("publication"), dict) and s["publication"].get("lag_alert")]
    if lag_samples:
        warnings.append(f"anchor publication lag alert active in {len(lag_samples)} sample(s)")

    success_rate = (c.results_ok / c.picked_up) if c.picked_up else None

    return {
        "started_utc": state.samples[0]["ts"] if state.samples else _now_iso(),
        "elapsed_seconds": round(elapsed, 1),
        "config": {"agents": cfg.agents, "duration_seconds": cfg.duration_seconds,
                   "heartbeat_interval": cfg.heartbeat_interval,
                   "dispatch_interval": cfg.dispatch_interval,
                   "sample_interval": cfg.sample_interval,
                   "outage_every": cfg.outage_every},
        "samples": len(state.samples),
        "counters": vars(c).copy(),
        "command_success_rate": success_rate,
        "rss_kb": rss,
        "open_fds": fds,
        "audit_intact_throughout": audit_intact_all,
        "outages_injected": outages,
        "outages_recovered": recovered,
        "critical_findings": state.critical,
        "warnings": warnings,
        "passed": len(state.critical) == 0,
    }


def _write_outputs(cfg: SoakConfig, state: SoakState, summary: dict) -> None:
    d = Path(cfg.evidence_dir)
    (d / "soak-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")

    lines = ["# NodeLink soak-test report", ""]
    lines.append(f"- Started: {summary['started_utc']}")
    lines.append(f"- Duration: {summary['elapsed_seconds']}s "
                 f"(target {summary['config']['duration_seconds']}s)")
    lines.append(f"- Agents: {summary['config']['agents']}")
    lines.append(f"- Samples: {summary['samples']}")
    lines.append(f"- **Result: {'PASS' if summary['passed'] else 'FAIL'}**")
    lines.append("")
    lines.append("## Workload")
    c = summary["counters"]
    sr = summary["command_success_rate"]
    lines.append(f"- Commands dispatched: {c['dispatched']} "
                 f"(admission-rejected 429: {c['dispatch_rejected_admission']}, "
                 f"errors: {c['dispatch_errors']})")
    lines.append(f"- Commands picked up / results OK: {c['picked_up']} / {c['results_ok']}"
                 + (f" (success rate {sr:.3f})" if sr is not None else ""))
    lines.append(f"- Heartbeats OK / errors: {c['heartbeats_ok']} / {c['heartbeats_err']}")
    lines.append(f"- Outages injected / recovered: "
                 f"{summary['outages_injected']} / {summary['outages_recovered']}")
    lines.append("")
    lines.append("## Resources")
    if summary["rss_kb"]:
        r = summary["rss_kb"]
        lines.append(f"- RSS (KiB): first {r['first']}, last {r['last']}, "
                     f"min {r['min']}, max {r['max']} over {r['samples']} samples")
    else:
        lines.append("- RSS: not sampled (no server PID available on this host)")
    if summary["open_fds"]:
        f = summary["open_fds"]
        lines.append(f"- Open FDs: first {f['first']}, last {f['last']}, max {f['max']}")
    lines.append("")
    lines.append("## Integrity")
    lines.append(f"- Audit chain intact at every sample: {summary['audit_intact_throughout']}")
    lines.append("")
    lines.append("## Findings")
    if summary["critical_findings"]:
        lines.append("### CRITICAL")
        for f in summary["critical_findings"]:
            lines.append(f"- {f}")
    if summary["warnings"]:
        lines.append("### Warnings (judge against docs/SOAK-TEST.md thresholds)")
        for w in summary["warnings"]:
            lines.append(f"- {w}")
    if not summary["critical_findings"] and not summary["warnings"]:
        lines.append("- None.")
    lines.append("")
    lines.append("Raw per-sample evidence: `soak-evidence.jsonl`. "
                 "Machine summary: `soak-summary.json`.")
    (d / "soak-report.md").write_text("\n".join(lines) + "\n")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base-url", default="http://127.0.0.1:8000")
    p.add_argument("--admin-email", required=True)
    p.add_argument("--admin-password", required=True)
    p.add_argument("--duration-seconds", type=float, default=3 * 24 * 3600)
    p.add_argument("--agents", type=int, default=25)
    p.add_argument("--heartbeat-interval", type=float, default=30.0)
    p.add_argument("--dispatch-interval", type=float, default=5.0)
    p.add_argument("--sample-interval", type=float, default=60.0)
    p.add_argument("--outage-every", type=float, default=900.0)
    p.add_argument("--outage-duration", type=float, default=120.0)
    p.add_argument("--server-pid", type=int, default=None,
                   help="PID of the server process to sample (auto-detected if omitted)")
    p.add_argument("--evidence-dir", default="./soak-evidence")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = SoakConfig(
        base_url=args.base_url, admin_email=args.admin_email,
        admin_password=args.admin_password, duration_seconds=args.duration_seconds,
        agents=args.agents, heartbeat_interval=args.heartbeat_interval,
        dispatch_interval=args.dispatch_interval, sample_interval=args.sample_interval,
        outage_every=args.outage_every, outage_duration=args.outage_duration,
        server_pid=args.server_pid if args.server_pid is not None else autodetect_server_pid(),
        evidence_dir=args.evidence_dir,
    )

    async def _run() -> dict:
        async with httpx.AsyncClient(base_url=cfg.base_url, timeout=30.0) as client:
            return await run_soak(client, cfg)

    summary = asyncio.run(_run())
    print(json.dumps({"passed": summary["passed"],
                      "critical": summary["critical_findings"],
                      "warnings": summary["warnings"],
                      "evidence_dir": cfg.evidence_dir}, indent=2))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
