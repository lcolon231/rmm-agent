# Agent enrollment open issues

Status values are `Open`, `Planned`, `Blocked`, `Accepted risk`, or `Resolved`.

## v0.1.2 issue map

The enrollment implementation is the code candidate for
[GitHub issue #33](https://github.com/lcolon231/rmm-agent/issues/33). The
following issues are pertinent to the v0.1.2 release decision:

| Issue | Release relationship | Disposition |
|---|---|---|
| [#127](https://github.com/lcolon231/rmm-agent/issues/127) | Immutable release manifest, PostgreSQL upgrade, verified backup, canary enrollment, and rollback evidence | **Tag blocker**; do not publish v0.1.2 until complete |
| [#128](https://github.com/lcolon231/rmm-agent/issues/128) | Next.js 16.2.12 transitive PostCSS/Sharp advisories | Resolved by exact Next-scoped patched dependencies, zero production audit, and production smoke evidence; close after the hardening PR merges |
| [#24](https://github.com/lcolon231/rmm-agent/issues/24) | Windows agent and installer remain unsigned | Existing pilot-exit blocker; must be explicit in release notes |
| [#125](https://github.com/lcolon231/rmm-agent/issues/125) | Agent credentials remain long-lived bearer credentials | Known security limitation; implement loss-safe expiry/renewal |
| [#126](https://github.com/lcolon231/rmm-agent/issues/126) | Empty deployments still need a client/site bootstrap path | Known onboarding limitation; existing client/site API bootstrap remains required |
| [#66](https://github.com/lcolon231/rmm-agent/issues/66) | Roles are global rather than tenant scoped | Do not market the release as multi-tenant |
| [#84](https://github.com/lcolon231/rmm-agent/issues/84) | Enrollment limiting and counters are process-local | Do not claim multi-worker/HA enrollment protection |

The release workflow requires `release-notes/v0.1.2.json`, but that file must
not be committed with invented backup URLs, artifact hashes, or rollback
results. Issue #127 owns creating it after the evidence exists.

| ID | Issue | Description | Security impact | Recommended decision | Owner | Status | Target release |
|---|---|---|---|---|---|---|---|
| ENR-001 | Agent credential type ([#125](https://github.com/lcolon231/rmm-agent/issues/125)) | Current agents use per-agent bearer keys; no device key pair or PKI exists. | Stolen bearer material can impersonate an agent. | Move to agent-generated Ed25519 keys and server-signed short-lived credentials; keep bearer keys only as the compatibility baseline. | Security | Planned | Post-v0.1.2 |
| ENR-002 | Organization-specific credentials | Agent credentials are bound to an agent row/site, not cryptographically to an organization. | Cross-tenant mistakes depend on server query correctness. | Bind organization and agent ID into signed credentials. | Security | Open | M2 |
| ENR-003 | Credential lifetime ([#125](https://github.com/lcolon231/rmm-agent/issues/125)) | Existing agent bearer credentials have no expiry. | Long compromise window. | Add 30-day credentials with automatic renewal and overlap bounded to one heartbeat interval. | Security | Planned | Post-v0.1.2 |
| ENR-004 | Credential renewal ([#125](https://github.com/lcolon231/rmm-agent/issues/125)) | No proven possession/renewal protocol exists. | Rotation could become an account-takeover path. | Require current credential plus agent private-key proof; rotate atomically. | Agent team | Open | Post-v0.1.2 |
| ENR-005 | Default token expiration | A usable operational default is not established. | Longer windows increase theft/replay opportunity. | Default to 24 hours. | Product security | Planned | M1 |
| ENR-006 | Maximum token expiration | No maximum currently exists. | Administrators can create effectively permanent enrollment access. | Cap at 30 days; require a new token after that. | Product security | Planned | M1 |
| ENR-007 | Reusable tokens | Limited-use tokens are supported but safe use cases are not defined. | One leak can enroll many rogue devices. | Single-use default; cap reusable tokens at 100 uses and 7 days; show elevated-risk warning. | Product | Planned | M1 |
| ENR-008 | Re-enrollment | Current revocation requires a new agent identity. | Duplicate records and unclear incident history. | Create a new identity and retain the prior agent as archived/revoked with a linkage event. | Product | Open | M2 |
| ENR-009 | Duplicate hostname | Multiple agents can share a hostname. | Ambiguous inventory and possible mistaken actions. | Allow but flag; never use hostname as identity. | Product | Open | M1 |
| ENR-010 | Agent identity validation | Host metadata is self-asserted during enrollment. | A token holder can claim any hostname/environment. | Treat metadata as claims; add attestation/PKI for high-assurance deployments. | Security | Open | M3 |
| ENR-011 | Agent deletion | Cascading deletion conflicts with durable audit needs. | Evidence can be lost or orphaned. | Do not expose delete; revoke and archive. | Compliance | Planned | M1 |
| ENR-012 | Offline threshold | Current threshold is heartbeat interval multiplied by three misses. | Poor tuning creates false status or delayed detection. | Keep configurable default; expose calculated threshold in UI. | Operations | Accepted risk | M1 |
| ENR-013 | Multi-tenant isolation ([#66](https://github.com/lcolon231/rmm-agent/issues/66)) | Clients/sites are not authorization tenants; roles are global. | A non-admin operator can access all customers. | Add operator-client memberships and mandatory server-side scoping before calling the product multi-tenant. | Architecture | Blocked | M3 |
| ENR-014 | Audit retention | Hash chaining/anchoring exists, but retention policy is not defined. | Evidence may be kept too briefly or violate privacy policy. | Set deployment-specific policy; recommended minimum seven years for regulated evidence after legal review. | Compliance | Open | M3 |
| ENR-015 | Secret-manager integration | CLI and installer do not integrate with deployment secret managers. | Tokens may leak into files or orchestration logs. | Support stdin/secret files now; add documented Vault/cloud secret-manager adapters. | Agent team | Open | M2 |
| ENR-016 | Proxy support | Agent relies on Go HTTP environment behavior but proxy operation is untested. | Enrollment may fail or bypass intended egress controls. | Test `HTTPS_PROXY`/`NO_PROXY`; document authenticated proxy limits. | Agent team | Open | M2 |
| ENR-017 | Certificate authority ownership | No NodeLink agent CA exists. | PKI responsibilities and recovery are undefined. | Customer-owned offline root with deployment-specific intermediate; support managed option later. | Security | Open | M3 |
| ENR-018 | Disaster recovery | Backup tooling exists; credential/CA recovery workflow is incomplete. | Restore can invalidate agents or fork trust state. | Include signing keys, limiter state requirements, and revocation evidence in encrypted DR plans and drills. | Operations | Open | M2 |
| ENR-019 | Token revocation propagation | Enrollment tokens are checked online, so revocation is immediate on one DB. | Replica lag could admit after revocation in HA. | Route redemption to the primary and use synchronous consistency for token rows. | Architecture | Open | M2 |
| ENR-020 | Agent credential revocation | Revocation is checked on each request; local identity remains. | Revoked secrets persist on disk. | Keep server-side immediate rejection; add agent self-wipe only under an authenticated signed revocation command. | Security | Open | M2 |
| ENR-021 | High-availability enrollment ([#84](https://github.com/lcolon231/rmm-agent/issues/84)) | Current API and limiter are process-local. | Limits multiply and concurrent primary topology is undefined. | Use PostgreSQL primary transactions plus shared Redis limiter before HA. | Architecture | Blocked | M4 |
| ENR-022 | Rate-limit thresholds | No production evidence supports a threshold. | Too low blocks rollout; too high permits guessing/DoS. | Start at 10 attempts/minute/IP with 60-second block; tune from redacted metrics. | Security | Planned | M1 |
| ENR-023 | IPv6 | Source-IP parsing exists but IPv6 proxy and limiter behavior lacks coverage. | Rate limiting may be bypassed with rotating IPv6 addresses. | Normalize IPv6 and optionally aggregate limiter keys by deployment-configured prefix. | Security | Open | M2 |
| ENR-024 | Installer signing ([#24](https://github.com/lcolon231/rmm-agent/issues/24)) | Windows installer is not Authenticode signed. | Users cannot strongly verify publisher; SmartScreen warnings. | Obtain hardware/cloud-backed EV signing and timestamp every release. | Release engineering | Blocked | M1 pilot exit |
| ENR-025 | Automated upgrades | Agent self-update is not implemented. | Vulnerable agents may remain deployed. | Signed manifest, staged rollout, rollback, and health gates. | Agent team | Open | M2 |
| ENR-026 | Linux/macOS credential storage | Non-Windows identity uses mode `0600`, not a keychain. | Root/user compromise reveals bearer material. | Integrate platform keychains before support designation. | Agent team | Accepted risk | M4 |
| ENR-027 | Token assignment to user | Operators exist, but endpoint-owner users do not. | `assigned_user` semantics are ambiguous. | Initially allow assignment only to an Operator ID as administrative metadata; add an end-user directory model separately. | Product | Open | M2 |
| ENR-028 | Central metrics stack | Repository has no Prometheus/OpenTelemetry dependency. | Operational detection is limited. | Expose bounded Prometheus text metrics or structured counters; choose a supported collector before HA. | Operations | Open | M2 |
| ENR-029 | CSRF token | Dashboard mutations use SameSite cookies and JSON same-origin handlers, but no synchronizer token. | Browser/platform changes or same-site subdomain compromise could increase risk. | Add Origin validation now; evaluate synchronizer tokens when more browser mutations are added. | Web security | Open | M2 |
| ENR-030 | First-run client/site setup ([#126](https://github.com/lcolon231/rmm-agent/issues/126)) | Token creation requires an existing site, but the enrollment area does not create the first client/site. | Administrators may resort to direct database changes or over-privileged bootstrap scripts. | Add an audited, role-protected client/site creation path and link it from enrollment empty states. | Dashboard team | Open | Post-v0.1.2 |
| ENR-031 | v0.1.2 operational evidence ([#127](https://github.com/lcolon231/rmm-agent/issues/127)) | Automated tests exist, but the production-like PostgreSQL upgrade, verified backup, canary, and rollback drill have not been retained. | A forward-only migration or credential rollout failure may not be recoverable within the expected RTO/RPO. | Complete the release evidence gate before tagging v0.1.2. | Release engineering | Blocked | v0.1.2 |
| ENR-032 | Dashboard dependency advisories ([#128](https://github.com/lcolon231/rmm-agent/issues/128)) | Next.js 16.2.12 declares vulnerable PostCSS/Sharp versions; exact Next-scoped overrides resolve PostCSS 8.5.23 and Sharp 0.35.3. | Production audit exposure is removed; compatibility risk is bounded by exact pins and the clean install/build/smoke suite. | Keep the exact pins until a stable Next.js release includes patched dependencies; reassess the dev-only lint toolchain by v0.1.3. | Dashboard security | Resolved | v0.1.2 |
