# Multi-day soak test

The soak test is the last gate before a controlled non-production pilot
(issue #77). It runs NodeLink under a sustained, realistic workload with
injected faults for several days and records objective evidence that the system
stays stable: no memory or descriptor leak, no audit-integrity break, commands
keep flowing, agents recover from outages, and external anchor publication keeps
up.

The harness (`deploy/soak/soak.py`) produces the evidence; the multi-day
**duration** is yours to run on a deployment that mirrors the pilot topology.
A compressed demonstration of the harness output is in
`deploy/soak/example-run/`.

## What it exercises

- Enrollment of N simulated agents, then continuous heartbeat/poll,
  command pickup, and buffered result submission — the endurance-relevant
  server paths.
- Operator command dispatch at a fixed rate, including admission control
  (429 `agent_command_queue_full`) when an agent's queue fills.
- Periodic agent **outages**: an agent goes dark for a window, then recovers;
  the harness records whether a heartbeat resumed afterward.
- A **sampler** that, every `--sample-interval`, records server process RSS and
  open file descriptors (leak detection), command counters, the audit-chain
  verification result, and external anchor publication lag/health.

## Running it

Prerequisites: a running NodeLink server (the pilot topology — TLS proxy,
PostgreSQL, `ENVIRONMENT=production`, an anchor publish backend configured per
`docs/AUDIT-ANCHORING.md`), an operator account, and — for resource sampling —
the ability to read the server process (same host, or sample separately).

```bash
python deploy/soak/soak.py \
  --base-url https://rmm.example.com \
  --admin-email you@example.com --admin-password '...' \
  --duration-seconds 259200 \        # 3 days
  --agents 25 \
  --heartbeat-interval 30 \
  --dispatch-interval 5 \
  --sample-interval 60 \
  --outage-every 900 --outage-duration 120 \
  --server-pid <uvicorn PID> \       # omit to auto-detect a local uvicorn
  --evidence-dir ./soak-evidence
```

The harness exits **non-zero** if any CRITICAL finding is recorded (the audit
chain broke, or the workload could not run), so it can gate a pipeline. It
writes three files into `--evidence-dir`:

- `soak-evidence.jsonl` — one JSON object per sample (raw evidence).
- `soak-summary.json` — machine-readable summary and findings.
- `soak-report.md` — the human report (workload, resources, integrity,
  findings).

### Restarts and the database

Two faults the harness cannot inject for you, because they are operational,
must be exercised during the window and noted in the pilot record:

- **Server restarts.** Restart the server (and, separately, the host) at least
  once mid-run. The workload should recover — the agent loops back off and
  resume, and audit verification should stay intact across the restart.
- **Backup + restore.** Take at least one encrypted backup during the run
  (`deploy/backup/nodelink-backup.sh`) and rehearse a restore into an isolated
  database (`docs/BACKUP-RESTORE.md`), confirming `verify_restore.py` passes on
  the mid-run snapshot.

## Acceptance thresholds

A run is acceptable for the pilot when:

| Signal | Threshold |
|--------|-----------|
| Audit chain | intact at **every** sample (any break is a hard block) |
| Command success rate | ≥ 0.99 of picked-up commands complete, excluding intended admission 429s |
| Heartbeat errors | near zero outside injected outages and restarts |
| Outage recovery | every injected outage shows a recovered heartbeat |
| Server RSS | no sustained upward trend; end-of-run RSS < 1.5× the settled baseline and not monotonically climbing |
| Open FDs | stable; end-of-run < 1.5× baseline (no descriptor leak) |
| Anchor publication | `pending` returns to 0 each cycle; no persistent `lag_alert` |
| Disk / DB growth | bounded and proportional to workload (watch externally) |

RSS and FD growth and publication lag are reported as **warnings**, not
automatic failures — a human judges them against these thresholds, because a
modest steady-state working set is expected. A leak looks like a monotonic
climb across the whole window, not a settled higher plateau.

## Findings and rerun criteria

Record, in the pilot report:

1. The run parameters, topology, and NodeLink version/commit.
2. The `soak-report.md` result and any warnings, with the operator's judgment
   on each warning against the thresholds above.
3. The restart and backup/restore observations.
4. Every CRITICAL or high finding, with resolution or an explicit decision that
   it blocks the pilot.

**Rerun** the soak (do not carry forward old evidence) after any change to:
the command path, the audit/anchor path, the agent runtime, the database
schema, or the deployment topology — anything that could alter the endurance or
integrity behavior the previous run measured.

## Automated coverage

`server/tests/test_soak_harness.py` runs the harness for a few seconds against
the in-process app on every CI run, verifying the workload flows, the counting
is exact, audit integrity holds, and the evidence/report files are well-formed —
so the harness itself cannot silently rot between real runs.
