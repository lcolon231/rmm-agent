# Competitive strategy

## Position

NodeLink is a self-hosted endpoint-management platform for regulated small
businesses and MSPs. It emphasizes signed and policy-controlled endpoint
actions, outbound-only connectivity, and independently verifiable
administrative audit records without the operational complexity of a broad RMM
suite.

NodeLink will not initially compete on total feature count and should not be
described as a full Tactical RMM replacement. Tactical RMM is significantly more
mature and publicly documents a dashboard, patch management, automated checks,
scheduled tasks, inventory, remote shell, file, registry, event-log and service
operations, software deployment, notifications, and MeshCentral-based remote
access. See the [Tactical RMM feature list](https://docs.tacticalrmm.com/),
[automation policies](https://docs.tacticalrmm.com/functions/automation_policies/),
and [MeshCentral integration](https://docs.tacticalrmm.com/mesh_integration/).
This comparison is about published product breadth, not a claim about Tactical
RMM's security or suitability for a particular customer.

## Initial customer profile

The first target customer is a small US-based business or MSP serving a limited
number of Windows-heavy, regulated SMB environments. The buyer values
self-hosting, understandable deployment, clear administrative accountability,
and exportable evidence more than a long integration catalog. Early pilots must
be non-critical, explicitly controlled, and operated by a technically capable
maintainer.

NodeLink is not initially intended for global enterprises, mixed-platform
fleets, high-availability control planes, consumer remote support, or customers
who need a mature all-in-one PSA/RMM ecosystem immediately.

## Differentiators

1. **Signed action boundary.** Endpoint actions evolve toward a versioned,
   expiring, nonce-bound, key-identified envelope that the agent verifies before
   execution.
2. **Policy before execution.** Sensitive actions can be restricted by typed
   operation, role, tenant, approval, time, and emergency-override policy.
3. **Verifiable evidence.** Audit records use deterministic sequencing,
   hash-linking, external anchors, and independently verifiable exports.
4. **Outbound-only endpoint connectivity.** Polling provides a simple resilient
   baseline, and later live transport does not remove that fallback.
5. **Windows-first focus.** Engineering and test effort concentrate on the
   operating environment used by the initial customers.
6. **Operational legibility.** Deployment, backup, recovery, upgrade, rollback,
   and evidence verification are treated as product requirements.

These are design goals until their roadmap issues are implemented and verified.
Documentation must always distinguish the current code from the intended design.

## Deliberately deferred

NodeLink defers Linux and macOS product support, a public API ecosystem, PSA
integrations, multi-region relays, high availability, community extensions,
and broad software-provider coverage until the Windows command, audit,
deployment, and technician workflows are reliable.

Interactive shell and remote desktop also follow the safer polling command path,
dashboard, inventory, monitoring, scheduling, patching, and typed remediation
work. Remote desktop will integrate MeshCentral rather than create a proprietary
protocol.

## Windows-first strategy

Windows-first means more than compiling a Windows binary. It requires automated
service lifecycle and installer tests, Authenticode-signed artifacts, DPAPI
credential protection, Windows security-state inventory, Windows Update and
reboot policy, Windows event/service/process/registry operations, soak tests,
and documented recovery on supported Windows versions.

Linux and macOS development builds may continue to catch portable-agent
regressions, but they must not be marketed as supported RMM agents before the
Milestone 4 support contract and test matrix exist.

## Business model possibilities

The near-term priority is validating product trust and technician usability, not
locking a commercial model. Maintainers should decide among:

- A fully open-source core with paid support, hosted operations, and deployment
  assistance.
- Open-core, keeping endpoint protocol and verification tooling open while
  offering hosted scale, enterprise identity, advanced evidence workflows, or
  integrations commercially.
- A commercial self-hosted distribution with source-available or open protocol
  components.

Any model should keep the command schemas and independent audit verification
open enough that customers can validate endpoint actions and evidence without
trusting a proprietary black box. Licensing, trademark, hosted-service scope,
and which features remain open require maintainer decisions before public
productization.

## Success metrics

### Deployment safety

- 100% of release Windows executables and installers are signed and verifiable.
- 100% of accepted commands use a supported signed-envelope version and active
  key ID.
- Zero unbounded command-output or uncontrolled-concurrency paths.
- Backup restore and rollback rehearsals meet documented recovery objectives.
- External audit-anchor publication and independent verification succeed on the
  defined schedule.

### Technician value

- A technician can enroll, locate, inspect, command, and audit an endpoint from
  the dashboard without direct API use.
- Time from installer launch to visible online endpoint is measured and reduced.
- Routine monitoring, script, patch, and remediation workflows expose complete
  status and failure reasons.

### Evidence quality

- Every sensitive action maps to an actor, tenant, policy/approval decision,
  endpoint, envelope, result, and ordered audit sequence.
- A clean environment can verify exported evidence without database access.
- Evidence export and retention tests pass for every supported format and
  policy.

### Reliability

- Multi-day Windows soak tests have no unexplained agent exit, lost result,
  unbounded resource growth, or unverifiable audit gap.
- Upgrade and rollback success rates, agent check-in health, task latency, and
  notification delivery are observable and have explicit targets before a paid
  launch.
