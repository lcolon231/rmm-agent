# NodeLink soak-test report

- Started: 2026-07-19T05:21:05.161650+00:00
- Duration: 180.8s (target 180.0s)
- Agents: 20
- Samples: 14
- **Result: PASS**

## Workload
- Commands dispatched: 346 (admission-rejected 429: 0, errors: 0)
- Commands picked up / results OK: 343 / 343 (success rate 1.000)
- Heartbeats OK / errors: 1179 / 0
- Outages injected / recovered: 3 / 3

## Resources
- RSS (KiB): first 103596, last 108620, min 103596, max 108620 over 14 samples
- Open FDs: first 18, last 24, max 27

## Integrity
- Audit chain intact at every sample: True

## Findings
- None.

Raw per-sample evidence: `soak-evidence.jsonl`. Machine summary: `soak-summary.json`.
