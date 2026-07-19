# Example soak run (compressed demonstration)

These files are the output of a **compressed** soak run used to demonstrate the
harness end to end — **not** the multi-day pilot evidence. They show the shape
of the evidence a real run produces and prove the harness, workload, fault
injection, resource sampling, audit verification, and external anchor
publication all work together against a live server.

Run parameters (see `soak-summary.json` for the full record):

- 3-minute duration, 20 simulated agents
- against a live `uvicorn` + PostgreSQL 16, with filesystem/WORM anchor
  publication enabled on a 10s interval
- 3 injected agent outages (20s each), all recovered
- 346 commands dispatched, 343 completed at a 1.000 success rate
- 1179 heartbeats, 0 errors
- RSS 103596 → 108620 KiB (≈5% over the window; well under the 1.5× warn
  threshold — no leak signature)
- audit chain intact at every one of 14 samples

The **real** pilot evidence is a multi-day run per `docs/SOAK-TEST.md`, whose
`soak-report.md`/`soak-summary.json`/`soak-evidence.jsonl` go into the pilot
record. `soak-evidence.sample.jsonl` here is a 4-line excerpt of the full
per-sample stream.
