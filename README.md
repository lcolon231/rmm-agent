# NodeLink RMM

A lightweight, self-hosted Remote Monitoring & Management platform built for MSPs serving SMB and medical-office clients. Designed as an open alternative to Atera / NinjaOne / Tactical RMM, with a focus on **outbound-only agent connectivity** and a **cryptographically verifiable audit trail** suitable for HIPAA-regulated environments.

## Why this exists

Commercial RMMs are priced per-endpoint and treat audit logging as an afterthought. NodeLink RMM is built around two principles that matter for medical-office compliance:

1. **No inbound firewall changes at client sites.** Agents connect *outbound* to the server over TLS. Nothing to port-forward, nothing to expose.
2. **Tamper-evident command history.** Every command executed on every endpoint is recorded in an append-only audit log, structured so it can be anchored to an external verification layer (see `docs/threat-model.md`).

## Architecture

```
┌─────────────┐         outbound TLS          ┌──────────────┐
│  Go Agent   │ ────── HTTPS (long-poll) ────► │ FastAPI      │
│ (Win svc)   │ ◄───── signed commands ─────── │ Server       │
└─────────────┘                                └──────┬───────┘
                                                      │
                                              ┌───────▼───────┐
                                              │  PostgreSQL   │
                                              └───────────────┘
                                                      ▲
                                              ┌───────┴───────┐
                                              │ Next.js       │
                                              │ Dashboard *   │
                                              └───────────────┘
```

> **What exists today:** the Go agent, the FastAPI server, and PostgreSQL. The
> agent reaches the server over **outbound HTTPS long-polling** — the heartbeat
> doubles as the command poll; a persistent WebSocket is planned, not built.
> The `*` marks the Next.js dashboard — Phase 2, **not yet in the repo**.

| Component | Stack | Status |
|-----------|-------|--------|
| `agent/` | Go — Windows service, check-in loop, PowerShell executor, inventory | Phase 1 |
| `server/` | FastAPI + PostgreSQL — enrollment, heartbeat, command queue, alerts | Phase 1 |
| `installer/` | Inno Setup — graphical Windows installer wrapping the agent | Phase 1 |
| `dashboard/` | Next.js — endpoint list, live status, command console | Phase 2 (planned, not yet in repo) |
| `docs/` | Architecture, threat model, deployment | ongoing |

## Roadmap

**Phase 1 (MVP)** — enrollment with one-time tokens, 60s heartbeat (CPU/RAM/disk/uptime), hardware + software inventory, offline alerting, remote PowerShell with streamed output.

**Phase 2** — Windows Update patch status, scheduled scripts, threshold alerts (disk >90%, etc.), Next.js dashboard.

**Phase 3** — remote desktop via embedded [MeshCentral](https://github.com/Ylianst/MeshCentral), agent self-update.

## Repo layout

```
rmm/
├── agent/        # Go agent (Windows service, check-in loop, executor)
├── installer/    # Inno Setup Windows installer for the agent
├── server/       # FastAPI backend
├── deploy/       # TLS-terminating reverse-proxy config (Caddyfile)
├── docs/         # architecture, threat model, deployment & release runbooks
└── dashboard/    # Next.js frontend — planned (Phase 2, not yet in the repo)
```

## Getting started

See [`server/README.md`](server/README.md) to run the backend, then [`agent/README.md`](agent/README.md) to build and enroll an agent.

To install the agent on a real Windows endpoint, use the graphical installer (`NodeLinkAgentSetup-<version>.exe`, attached to each [release](https://github.com/lcolon231/rmm-agent/releases)) — it prompts for the server URL and enrollment token and registers the service for you. See [`installer/README.md`](installer/README.md).

## License

TBD — private during initial development.
