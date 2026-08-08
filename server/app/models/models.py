# SPDX-License-Identifier: AGPL-3.0-only
"""ORM models for NodeLink RMM.

Entity overview:

    Client         a customer org (e.g. "Bayshore Family Practice")
      └─ Site      a physical/logical location under a client
           └─ EnrollmentToken   one-time token used to enroll agents at a site
           └─ Agent             an enrolled endpoint
                └─ Heartbeat     periodic telemetry sample
                └─ Command       a queued/executed instruction
                └─ AuditEvent    append-only record of anything meaningful
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    JSON,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class OperatorRole(str, enum.Enum):
    """What a human operator may do. Ordered from least to most privilege.

    readonly  -> can view clients, sites, agents, command history, audit
    operator  -> everything readonly can, plus provisioning and dispatching
    admin     -> everything, plus managing other operators
    """
    readonly = "readonly"
    operator = "operator"
    admin = "admin"


class ScriptExecutionScope(str, enum.Enum):
    """The single explicit arbitrary-script boundary granted to an operator."""

    global_ = "global"
    site = "site"
    agent = "agent"


class AgentStatus(str, enum.Enum):
    pending = "pending"      # enrolled, no heartbeat yet
    online = "online"
    offline = "offline"


class AgentTrustState(str, enum.Enum):
    """Whether the server still trusts an agent's credentials. Deliberately
    separate from AgentStatus: online/offline says whether the machine is
    reachable, trust says whether we will act on its behalf at all.

    active      -> normal operation
    quarantined -> authenticates, but receives no commands and may not submit
                   results; reversible by an operator
    revoked     -> credentials fail authentication entirely; terminal — the
                   machine must re-enroll under a new identity
    """
    active = "active"
    quarantined = "quarantined"
    revoked = "revoked"


class EnrollmentTokenStatus(str, enum.Enum):
    active = "active"
    used = "used"
    expired = "expired"
    revoked = "revoked"


class CommandKind(str, enum.Enum):
    powershell = "powershell"
    shell = "shell"
    collect_inventory = "collect_inventory"


class CommandStatus(str, enum.Enum):
    queued = "queued"
    dispatched = "dispatched"
    running = "running"
    result_pending = "result_pending"
    succeeded = "succeeded"
    failed = "failed"
    expired = "expired"


class ShellSessionStatus(str, enum.Enum):
    """Lifecycle of an interactive shell session (issue #61).

    pending    -> authorized and created; the agent has not yet attached
    active     -> the agent attached; streaming I/O may flow
    closed     -> ended normally by the operator or agent
    denied     -> refused at open time (kept only when a row is persisted)
    timed_out  -> ended by the server on idle or absolute-lifetime expiry
    failed     -> ended on a transport/limit fault (fail closed)

    Terminal states are closed, denied, timed_out, and failed.
    """

    pending = "pending"
    active = "active"
    closed = "closed"
    denied = "denied"
    timed_out = "timed_out"
    failed = "failed"


class ScheduleTargetType(str, enum.Enum):
    agent = "agent"
    site = "site"


class ScheduleConcurrencyPolicy(str, enum.Enum):
    skip = "skip"
    queue = "queue"
    allow = "allow"


class ScheduleMisfirePolicy(str, enum.Enum):
    run_once = "run_once"
    skip = "skip"


class MonitoringScope(str, enum.Enum):
    """Where a monitoring policy or maintenance window applies (issue #41).

    Ordered least- to most-specific. Effective policy for an agent merges the
    applicable levels with most-specific-wins, so a per-agent policy overrides
    the site, client, and global ones for the same check. A client level is
    included beyond ``ScriptExecutionScope`` because MSPs manage monitoring at
    the customer boundary, not only per site.
    """

    global_ = "global"
    client = "client"
    site = "site"
    agent = "agent"


class CheckType(str, enum.Enum):
    """The check kinds a policy may configure and #42 evaluates."""

    offline = "offline"
    cpu = "cpu"
    memory = "memory"
    disk = "disk"
    service = "service"
    reboot_pending = "reboot_pending"
    uptime = "uptime"


class CheckResultStatus(str, enum.Enum):
    """Evaluation outcome for one check on one agent.

    ``unknown`` is distinct from ``ok``: it means the check could not be
    evaluated (the agent did not report, or the metric was unavailable), which
    a technician must be able to tell apart from a passing check.
    """

    ok = "ok"
    warning = "warning"
    critical = "critical"
    unknown = "unknown"


class AlertState(str, enum.Enum):
    """Lifecycle state for one deduplicated monitoring alert.

    #43 drives ``open`` and automatic ``resolved`` transitions. The
    ``acknowledged`` value is reserved for #44's role-gated technician action
    so mixed server versions share one stable database contract.
    """

    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"


class AlertEventType(str, enum.Enum):
    """Immutable lifecycle transitions and technician actions (#44)."""

    state_imported = "state_imported"
    opened = "opened"
    reopened = "reopened"
    acknowledged = "acknowledged"
    assigned = "assigned"
    commented = "commented"
    manual_resolution = "manual_resolution"
    automatic_recovery = "automatic_recovery"
    policy_revised = "policy_revised"
    policy_deleted = "policy_deleted"
    policy_superseded = "policy_superseded"


class EmailDeliveryStatus(str, enum.Enum):
    """Durable state for one alert email recipient (#45)."""

    pending = "pending"
    sending = "sending"
    retrying = "retrying"
    sent = "sent"
    failed = "failed"
    suppressed = "suppressed"


class EmailAttemptStatus(str, enum.Enum):
    """Immutable outcome for one provider call."""

    sending = "sending"
    sent = "sent"
    retrying = "retrying"
    failed = "failed"


class WebhookDeliveryStatus(str, enum.Enum):
    """Durable state for one signed webhook event delivery (#46)."""

    pending = "pending"
    sending = "sending"
    retrying = "retrying"
    delivered = "delivered"
    failed = "failed"
    suppressed = "suppressed"


class WebhookAttemptStatus(str, enum.Enum):
    """Immutable outcome for one pinned webhook HTTP request."""

    sending = "sending"
    delivered = "delivered"
    retrying = "retrying"
    failed = "failed"


class ScriptLanguage(str, enum.Enum):
    """Script interpreters supported by the Milestone 1 library."""

    powershell = "powershell"
    shell = "shell"


class ScriptReviewState(str, enum.Enum):
    """Final review decisions. No row means the version is still a draft."""

    approved = "approved"
    rejected = "rejected"


class ScriptParameterKind(str, enum.Enum):
    """Supported immutable script parameter definition kinds (issue #48)."""

    string = "string"
    number = "number"
    boolean = "boolean"
    choice = "choice"
    secret = "secret"


class Client(Base):
    __tablename__ = "clients"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    sites: Mapped[list["Site"]] = relationship(
        back_populates="client", cascade="all, delete-orphan"
    )


class Operator(Base):
    """A human user of the RMM. Distinct from an Agent (a machine)."""
    __tablename__ = "operators"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[OperatorRole] = mapped_column(
        Enum(OperatorRole), default=OperatorRole.readonly, nullable=False
    )
    # Arbitrary PowerShell/shell execution is independently default-denied,
    # including for admins. A non-NULL scope is an explicit permission grant;
    # scope_id is required for site/agent scopes and NULL for global.
    script_execution_scope: Mapped[ScriptExecutionScope | None] = mapped_column(
        Enum(ScriptExecutionScope), nullable=True
    )
    script_execution_scope_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True
    )
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # Monotonic token version. Every JWT carries the generation it was minted
    # under; bumping this immediately invalidates all outstanding tokens for
    # this operator (logout-everywhere / revocation after a suspected leak).
    token_generation: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Site(Base):
    __tablename__ = "sites"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    client_id: Mapped[str] = mapped_column(
        ForeignKey("clients.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    client: Mapped["Client"] = relationship(back_populates="sites")
    agents: Mapped[list["Agent"]] = relationship(
        back_populates="site", cascade="all, delete-orphan"
    )
    enrollment_tokens: Mapped[list["EnrollmentToken"]] = relationship(
        back_populates="site", cascade="all, delete-orphan"
    )


Index(
    "ux_clients_name_normalized",
    func.lower(func.trim(Client.name)),
    unique=True,
)
Index(
    "ux_sites_client_name_normalized",
    Site.client_id,
    func.lower(func.trim(Site.name)),
    unique=True,
)


class EnrollmentToken(Base):
    """One-time (or limited-use) token that lets an installer enroll agents at a
    specific site. We store only the hash; the plaintext is shown once at
    creation and handed to the installer."""
    __tablename__ = "enrollment_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    site_id: Mapped[str] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # Non-secret support identifier. This is deliberately only the first few
    # characters of the random token and is safe to show in masked list views.
    token_prefix: Mapped[str] = mapped_column(String(12), default="", nullable=False)
    name: Mapped[str] = mapped_column(String(200), default="Enrollment token", nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    label: Mapped[str | None] = mapped_column(String(200))
    assigned_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("operators.id", ondelete="SET NULL"), index=True
    )
    environment: Mapped[str | None] = mapped_column(String(100))
    hostname_restriction: Mapped[str | None] = mapped_column(String(255))
    agent_name_restriction: Mapped[str | None] = mapped_column(String(255))
    labels: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    max_uses: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    uses: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    created_by_id: Mapped[str | None] = mapped_column(
        ForeignKey("operators.id", ondelete="SET NULL"), index=True
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by_id: Mapped[str | None] = mapped_column(
        ForeignKey("operators.id", ondelete="SET NULL"), index=True
    )
    notes: Mapped[str | None] = mapped_column(Text)

    site: Mapped["Site"] = relationship(back_populates="enrollment_tokens")
    assigned_user: Mapped["Operator | None"] = relationship(
        foreign_keys=[assigned_user_id]
    )
    created_by: Mapped["Operator | None"] = relationship(
        foreign_keys=[created_by_id]
    )
    revoked_by: Mapped["Operator | None"] = relationship(
        foreign_keys=[revoked_by_id]
    )

    @property
    def status(self) -> EnrollmentTokenStatus:
        if self.revoked or self.revoked_at is not None:
            return EnrollmentTokenStatus.revoked
        if self.expires_at is None:
            # Legacy tokens without an expiry fail closed.
            return EnrollmentTokenStatus.expired
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp <= datetime.now(timezone.utc):
            return EnrollmentTokenStatus.expired
        if self.uses >= self.max_uses:
            return EnrollmentTokenStatus.used
        return EnrollmentTokenStatus.active

    @property
    def is_usable(self) -> bool:
        return self.status == EnrollmentTokenStatus.active


class InstallerDownload(Base):
    """Audit/retention record for one personalized installer download (issue #9).

    A technician downloads a site-scoped package that bundles the stock signed
    installer with a short-lived, single-use enrollment token. Only metadata is
    stored here: the token's secret lives (hashed) on the linked EnrollmentToken,
    never on this row. The record supports the download audit trail, expiry/
    revocation display, and retention cleanup.
    """
    __tablename__ = "installer_downloads"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    site_id: Mapped[str] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # The single-use token minted into this package. SET NULL keeps the download
    # record if the token row is ever pruned.
    enrollment_token_id: Mapped[str | None] = mapped_column(
        ForeignKey("enrollment_tokens.id", ondelete="SET NULL"), index=True
    )
    created_by_id: Mapped[str | None] = mapped_column(
        ForeignKey("operators.id", ondelete="SET NULL"), index=True
    )
    created_by_email: Mapped[str | None] = mapped_column(String(320))
    # Which stock artifact was shipped, and its verified digest — evidence the
    # download carried a known, untampered installer.
    artifact_version: Mapped[str] = mapped_column(String(100), default="", nullable=False)
    artifact_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    site_id: Mapped[str] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False
    )
    # SHA-256 of the agent's long-lived bearer token.
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    credential_fingerprint: Mapped[str | None] = mapped_column(String(64), index=True)
    credential_issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    credential_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Loss-safe rotation overlap (issue #125). On renewal the just-superseded
    # bearer moves here and stays valid until previous_token_expires_at, a
    # bounded window, so a dropped renewal response never strands the agent —
    # it keeps authenticating on the old credential and retries.
    previous_token_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    previous_token_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    # Monotonic rotation counter (lineage/audit) and the last rotation nonce, so
    # a verbatim renewal replay (same nonce) is rejected while a genuine retry
    # with a fresh nonce is not.
    credential_generation: Mapped[int] = mapped_column(
        Integer, default=1, server_default="1", nullable=False
    )
    last_rotation_nonce: Mapped[str | None] = mapped_column(String(64))
    last_renewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    name: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    os: Mapped[str] = mapped_column(String(100), default="")
    os_version: Mapped[str] = mapped_column(String(100), default="")
    agent_version: Mapped[str] = mapped_column(String(50), default="")
    architecture: Mapped[str] = mapped_column(String(100), default="", nullable=False)
    environment: Mapped[str | None] = mapped_column(String(100))
    labels: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    owner_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("operators.id", ondelete="SET NULL"), index=True
    )
    enrolled_by_token_id: Mapped[str | None] = mapped_column(
        ForeignKey("enrollment_tokens.id", ondelete="SET NULL"), index=True
    )
    ip_address: Mapped[str | None] = mapped_column(String(64))
    # Versions this agent most recently advertised. Empty means commands fail
    # closed until a compatible agent checks in.
    command_envelope_versions: Mapped[list[str]] = mapped_column(
        JSON, default=list, nullable=False
    )
    # Optional feature capabilities this agent most recently advertised (issue
    # #61), e.g. "shell-session-v1". NULL/empty means the agent predates or does
    # not support the capability, so features that require it fail closed as
    # "unsupported" rather than being offered.
    supported_capabilities: Mapped[list[str] | None] = mapped_column(JSON)

    status: Mapped[AgentStatus] = mapped_column(
        Enum(AgentStatus), default=AgentStatus.pending
    )
    trust_state: Mapped[AgentTrustState] = mapped_column(
        Enum(AgentTrustState), default=AgentTrustState.active, nullable=False
    )
    trust_state_reason: Mapped[str | None] = mapped_column(Text)
    trust_state_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    trust_state_changed_by: Mapped[str | None] = mapped_column(String(320))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    enrolled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Latest inventory snapshot (hardware + installed software), stored as JSON.
    inventory: Mapped[dict | None] = mapped_column(JSON)

    site: Mapped["Site"] = relationship(back_populates="agents")
    owner_user: Mapped["Operator | None"] = relationship(foreign_keys=[owner_user_id])
    enrolled_by_token: Mapped["EnrollmentToken | None"] = relationship(
        foreign_keys=[enrolled_by_token_id]
    )
    heartbeats: Mapped[list["Heartbeat"]] = relationship(
        back_populates="agent", cascade="all, delete-orphan"
    )
    commands: Mapped[list["Command"]] = relationship(
        back_populates="agent", cascade="all, delete-orphan"
    )


class Heartbeat(Base):
    __tablename__ = "heartbeats"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    agent_id: Mapped[str] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)

    cpu_percent: Mapped[float] = mapped_column(Float, default=0.0)
    mem_percent: Mapped[float] = mapped_column(Float, default=0.0)
    disk_percent: Mapped[float] = mapped_column(Float, default=0.0)
    uptime_seconds: Mapped[int] = mapped_column(Integer, default=0)
    logged_in_user: Mapped[str | None] = mapped_column(String(255))

    agent: Mapped["Agent"] = relationship(back_populates="heartbeats")


class Command(Base):
    __tablename__ = "commands"
    __table_args__ = (
        # Global task-run history (issue #50) orders newest-first across every
        # endpoint and filters by created_at range; index the sort/range key.
        Index("ix_commands_created_at", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    agent_id: Mapped[str] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[CommandKind] = mapped_column(Enum(CommandKind), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    envelope_version: Mapped[str] = mapped_column(String(32), nullable=False)
    schema_version: Mapped[int | None] = mapped_column(Integer)
    issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    nonce: Mapped[str | None] = mapped_column(String(64))
    signing_key_id: Mapped[str | None] = mapped_column(String(64))
    # Base64 Ed25519 signature over the canonical command bytes.
    signature: Mapped[str] = mapped_column(Text, default="")

    status: Mapped[CommandStatus] = mapped_column(
        Enum(CommandStatus), default=CommandStatus.queued, index=True
    )
    exit_code: Mapped[int | None] = mapped_column(Integer)
    # SENSITIVE (issue #112): captured command output can contain endpoint
    # secrets. It is classified sensitive data: only ever returned through the
    # role-gated, audited command-detail read (command_detail.viewed), never
    # copied into audit-event detail, logs, or diagnostics. Do not add it to an
    # audit `detail`, a log line, or an error message.
    stdout: Mapped[str | None] = mapped_column(Text)
    stderr: Mapped[str | None] = mapped_column(Text)
    # Truncation evidence from the agent's bounded capture. NULL means the
    # result predates output limits (or none was reported) — unknown, not
    # "complete". The totals are the byte counts the child actually produced.
    stdout_truncated: Mapped[bool | None] = mapped_column(Boolean)
    stderr_truncated: Mapped[bool | None] = mapped_column(Boolean)
    stdout_total_bytes: Mapped[int | None] = mapped_column(BigInteger)
    stderr_total_bytes: Mapped[int | None] = mapped_column(BigInteger)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Agent-local completion time reported from the durable result outbox.
    # completed_at remains the server acknowledgement/persistence time.
    agent_completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Run provenance (issue #50). Answers "who ran what, from where" on the run
    # row itself, not just in the tamper-evident audit log. All nullable so the
    # column set is backfill-free: NULL means "not recorded" (e.g. historic rows
    # or ad-hoc commands with no library origin), never a positive claim.
    #
    # The operator who dispatched the run. actor_email is denormalized for
    # display; actor_operator_id is the durable link (SET NULL if the operator is
    # later removed, so the run record survives).
    actor_email: Mapped[str | None] = mapped_column(String(320))
    actor_operator_id: Mapped[str | None] = mapped_column(
        ForeignKey("operators.id", ondelete="SET NULL"), index=True
    )
    # Script-library origin, when the run came from a reviewed script version and
    # (optionally) a captured parameter value set. RESTRICT would block deleting
    # referenced versions; the library keeps versions immutable, so a plain FK is
    # enough and SET NULL preserves the run if a value set is ever purged.
    script_version_id: Mapped[str | None] = mapped_column(
        ForeignKey("script_versions.id", ondelete="SET NULL"), index=True
    )
    script_parameter_value_set_id: Mapped[str | None] = mapped_column(
        ForeignKey("script_parameter_value_sets.id", ondelete="SET NULL")
    )
    # Link to the command.dispatched audit event so a run points back at its
    # place in the hash chain. SET NULL keeps the run if audit is ever pruned.
    dispatch_audit_event_id: Mapped[str | None] = mapped_column(
        ForeignKey("audit_events.id", ondelete="SET NULL")
    )
    # Forward-compat lifecycle/lineage for recurring scheduling (#49) and retries.
    # No producer populates these yet; they land now so scheduling/retry work
    # needs no second migration. planned_at is the scheduled fire time; attempt
    # numbers a run within its retry lineage; parent_command_id chains a retry to
    # the run it superseded.
    planned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempt: Mapped[int] = mapped_column(
        Integer, default=1, server_default="1", nullable=False
    )
    parent_command_id: Mapped[str | None] = mapped_column(
        ForeignKey("commands.id", ondelete="SET NULL")
    )

    agent: Mapped["Agent"] = relationship(back_populates="commands")


class ShellSession(Base):
    """An authorized, bounded, audited interactive shell session (issue #61).

    Phase 1 persists only the session lifecycle and its bounds/evidence — never
    the streamed input or output bytes, which are sensitive exactly like
    ``Command.stdout``/``stderr`` and are relayed through a bounded in-memory
    channel in a later phase. The row is the durable record an operator and the
    audit log point at: who opened it, against which agent, under what limits,
    and how it ended.
    """

    __tablename__ = "shell_sessions"
    __table_args__ = (
        Index("ix_shell_sessions_agent_status", "agent_id", "status"),
        Index("ix_shell_sessions_created_at", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    agent_id: Mapped[str] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # The operator who opened the session. actor_email is denormalized for
    # display; operator_id is the durable link (SET NULL if the operator is
    # later removed, so the session record survives).
    operator_id: Mapped[str | None] = mapped_column(
        ForeignKey("operators.id", ondelete="SET NULL"), index=True
    )
    actor_email: Mapped[str | None] = mapped_column(String(320))

    status: Mapped[ShellSessionStatus] = mapped_column(
        Enum(ShellSessionStatus),
        default=ShellSessionStatus.pending,
        nullable=False,
        index=True,
    )
    # The negotiated agent capability that authorized this session, e.g.
    # "shell-session-v1"; recorded so a later protocol revision stays auditable.
    capability_version: Mapped[str | None] = mapped_column(String(64))
    close_reason: Mapped[str | None] = mapped_column(String(64))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_activity_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Server-authoritative deadlines. absolute_deadline caps total lifetime;
    # idle_deadline is pushed forward on each I/O frame and caps inactivity.
    absolute_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    idle_deadline: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Bounds and running evidence (byte/frame counters, sequence high-water
    # marks). No I/O payloads are ever stored here.
    output_bytes_limit: Mapped[int | None] = mapped_column(BigInteger)
    output_bytes_total: Mapped[int] = mapped_column(
        BigInteger, default=0, server_default="0", nullable=False
    )
    frames_out: Mapped[int] = mapped_column(
        BigInteger, default=0, server_default="0", nullable=False
    )
    frames_in: Mapped[int] = mapped_column(
        BigInteger, default=0, server_default="0", nullable=False
    )
    client_last_seq: Mapped[int] = mapped_column(
        BigInteger, default=0, server_default="0", nullable=False
    )
    agent_last_seq: Mapped[int] = mapped_column(
        BigInteger, default=0, server_default="0", nullable=False
    )

    agent: Mapped["Agent"] = relationship()


class AuditEvent(Base):
    """Append-only audit record. Never updated or deleted in normal operation.

    `prev_hash` + `event_hash` form a hash chain per the threat model: each
    event commits to the previous one, so any tampering downstream is
    detectable. This is the on-ramp to the external anchoring layer described
    in docs/threat-model.md.
    """
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    # Strictly monotonic position in the chain, assigned in a serialized
    # append (1, 2, 3, ... with no gaps). This — not the wall-clock ts — is
    # the canonical order for verification and anchoring; a unique constraint
    # makes a lost append race an error instead of a silent fork.
    seq: Mapped[int | None] = mapped_column(BigInteger, unique=True, index=True)
    # Hash schema 1 = legacy (seq not bound into event_hash, assigned by
    # backfill); 2 = seq is part of the hashed document. Once the chain
    # contains a schema-2 event, schema-1 events may not follow.
    hash_schema: Mapped[int] = mapped_column(Integer, default=2, nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    # Canonical ISO-8601 string actually used to compute event_hash. Storing it
    # explicitly makes verification independent of how the DB round-trips
    # timezone-aware datetimes.
    ts_iso: Mapped[str] = mapped_column(String(40), default="")
    actor: Mapped[str] = mapped_column(String(255), default="system")
    actor_user_id: Mapped[str | None] = mapped_column(String(36), index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    agent_id: Mapped[str | None] = mapped_column(String(36), index=True)
    enrollment_token_id: Mapped[str | None] = mapped_column(String(36), index=True)
    organization_id: Mapped[str | None] = mapped_column(String(36), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(500))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)

    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    event_hash: Mapped[str] = mapped_column(String(64), default="", index=True)


class AuditAnchor(Base):
    """A Merkle commitment over a prefix of the audit chain.

    Each anchor covers the first `event_count` events in (ts, id) order and
    stores the Merkle root of their `event_hash` values. The root is the unit
    of EXTERNAL anchoring: publish it to an append-only medium outside this
    system (transparency log, on-chain, even a signed email thread). An anchor
    row in this database proves nothing by itself against an attacker who owns
    the database — its value comes from the copies that exist elsewhere.
    """
    __tablename__ = "audit_anchors"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    # How many events (in ascending seq order from the start of the chain) this
    # anchor covers, and the last covered event for a cheap consistency check.
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    last_event_id: Mapped[str] = mapped_column(String(36), nullable=False)
    merkle_root: Mapped[str] = mapped_column(String(64), nullable=False)

    publications: Mapped[list["AnchorPublication"]] = relationship(
        back_populates="anchor", cascade="all, delete-orphan"
    )


class AnchorPublication(Base):
    """Record of publishing one anchor's Merkle root to one external immutable
    destination — the thing that makes the root un-rewritable by an attacker
    who owns this database.

    `receipt` is the destination's proof of publication (an S3 object
    version-id + ETag, a transparency-log inclusion proof, etc.), stored as
    JSON with NO credentials in it. `receipt_sha256` is a hash over the
    canonical receipt so a later tamper with the stored receipt is detectable.
    A row is unique per (anchor, backend): re-publishing after a crash writes
    the same deterministic destination key and reconciles onto this row rather
    than forking.
    """
    __tablename__ = "anchor_publications"
    __table_args__ = (
        UniqueConstraint("anchor_id", "backend", name="ux_anchor_publication_backend"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    anchor_id: Mapped[str] = mapped_column(
        ForeignKey("audit_anchors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    backend: Mapped[str] = mapped_column(String(32), nullable=False)
    # pending -> published; a failed attempt stays pending (with last_error set)
    # so the scheduler retries it.
    status: Mapped[str] = mapped_column(String(16), default="pending", nullable=False)
    uri: Mapped[str | None] = mapped_column(String(1024))
    receipt: Mapped[dict | None] = mapped_column(JSON)
    receipt_sha256: Mapped[str | None] = mapped_column(String(64))
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    anchor: Mapped["AuditAnchor"] = relationship(back_populates="publications")


class AgentInventorySnapshot(Base):
    """One collected inventory section for one agent (issue #35).

    Rows are append-only and inserted only when a section's ``content_hash``
    changes, so the table is simultaneously the current state (the newest row
    per ``(agent_id, section)``) and the change history that #40 renders as
    diffs. Storing one row per section — rather than one document per agent —
    means later inventory classes are new ``section`` values, not migrations.
    """

    __tablename__ = "agent_inventory_snapshots"
    __table_args__ = (
        Index(
            "ix_agent_inventory_agent_section_received",
            "agent_id",
            "section",
            "received_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    agent_id: Mapped[str] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    section: Mapped[str] = mapped_column(String(32), nullable=False)
    # 32 rather than 16: "permission_denied" is 17 characters. SQLite ignores
    # VARCHAR length, so an under-sized column here fails only on PostgreSQL.
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    # SHA-256 over the canonical section payload. Dedup key and the value the
    # agent compares against to decide whether a resend is worth the bytes.
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    # When the endpoint collected it, versus when we received it. A large gap
    # means a queued or clock-skewed endpoint, which a technician needs to see
    # before trusting the values.
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False, index=True
    )

    agent: Mapped["Agent"] = relationship()


# --------------------------------------------------------------------------- #
# Monitoring (issue #41)
# --------------------------------------------------------------------------- #
class MonitoringPolicy(Base):
    """A named set of monitoring checks bound to a scope (issue #41).

    The row is the stable *identity* — name, scope, enabled flag. Its check
    content is held in append-only :class:`MonitoringPolicyRevision` rows, so a
    policy's history is preserved and every edit is an auditable new version.
    ``scope_id`` is the id of the client/site/agent the policy targets, and is
    NULL for a global policy, mirroring ``Operator.script_execution_scope_id``.
    """

    __tablename__ = "monitoring_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    scope: Mapped[MonitoringScope] = mapped_column(
        Enum(MonitoringScope, values_callable=lambda enum_type: [item.value for item in enum_type]),
        nullable=False,
    )
    # NULL only for the global scope. Not a hard FK: it addresses one of three
    # different tables (clients/sites/agents) depending on scope, and the scope
    # column is what disambiguates which. Referential integrity is enforced in
    # the API when a policy is created.
    scope_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    revisions: Mapped[list["MonitoringPolicyRevision"]] = relationship(
        back_populates="policy", cascade="all, delete-orphan"
    )


# One policy name per scope target, case- and whitespace-insensitive, matching
# the client/site normalization rule. Standard SQL treats NULL scope_ids as
# distinct, so this index does not by itself block duplicate *global* names; the
# API enforces duplicate-name rejection for every scope (this index is
# defense-in-depth for the client/site/agent cases).
Index(
    "ux_monitoring_policies_scope_name_normalized",
    MonitoringPolicy.scope,
    MonitoringPolicy.scope_id,
    func.lower(func.trim(MonitoringPolicy.name)),
    unique=True,
)


class MonitoringPolicyRevision(Base):
    """One immutable version of a policy's check set (issue #41).

    Appended on every edit; the current revision is the highest ``version`` for
    a policy. ``checks`` is a bounded, schema-validated JSON list (validated by
    ``app/schemas/monitoring.py`` before storage), so adding a new check type is
    a schema change, not a migration.
    """

    __tablename__ = "monitoring_policy_revisions"
    __table_args__ = (
        UniqueConstraint(
            "policy_id", "version", name="ux_monitoring_policy_revision_version"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    policy_id: Mapped[str] = mapped_column(
        ForeignKey("monitoring_policies.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    checks: Mapped[list] = mapped_column(JSON, nullable=False)
    change_note: Mapped[str | None] = mapped_column(Text)
    # Operator email, for provenance in the revision history. Kept denormalized
    # so a deleted operator does not erase who last changed a live policy.
    created_by: Mapped[str | None] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    policy: Mapped["MonitoringPolicy"] = relationship(back_populates="revisions")


class MaintenanceWindow(Base):
    """A scoped time span during which alerting is suppressed (issue #41).

    #41 defines the model and its authorized CRUD; the suppression *enforcement*
    during alert evaluation is #43/#44. Scope/scope_id follow the same rule as
    :class:`MonitoringPolicy`.
    """

    __tablename__ = "maintenance_windows"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    scope: Mapped[MonitoringScope] = mapped_column(
        Enum(MonitoringScope, values_callable=lambda enum_type: [item.value for item in enum_type]),
        nullable=False,
    )
    scope_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class CheckResult(Base):
    """One check evaluation for one agent (issue #41).

    #42's authenticated agent ingestion and server-owned offline evaluation
    write through the #41 storage seam. Rows are append-only and retained
    newest-N per ``(agent_id,
    check_key)``, mirroring inventory-snapshot retention.
    """

    __tablename__ = "check_results"
    __table_args__ = (
        Index(
            "ix_check_results_agent_key_received",
            "agent_id",
            "check_key",
            "received_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    agent_id: Mapped[str] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # The policy/revision the evaluation was made against, for provenance. Not a
    # hard FK to the revision so pruning old revisions never orphans results.
    policy_id: Mapped[str | None] = mapped_column(String(36))
    policy_revision_id: Mapped[str | None] = mapped_column(String(36))
    # Stable key of the check within the effective policy.
    check_key: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[CheckResultStatus] = mapped_column(
        Enum(
            CheckResultStatus,
            values_callable=lambda enum_type: [item.value for item in enum_type],
        ),
        nullable=False,
    )
    value: Mapped[float | None] = mapped_column(Float)
    detail: Mapped[dict | None] = mapped_column(JSON)
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False, index=True
    )

    agent: Mapped["Agent"] = relationship()


class Alert(Base):
    """Current state of one policy/endpoint/check alert identity (#43).

    A row is reused across automatic recovery and retrigger cycles. This keeps
    one logical alert per identity while ``generation`` and the current/lifetime
    occurrence counters preserve incident boundaries. Policy ids are retained
    as provenance rather than foreign keys so deleting a policy cannot erase
    its operational evidence.
    """

    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint(
            "agent_id", "policy_id", "check_key", name="ux_alert_identity"
        ),
        Index("ix_alerts_state_last_observed", "state", "last_observed_at"),
        Index("ix_alerts_agent_state", "agent_id", "state"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    agent_id: Mapped[str] = mapped_column(
        ForeignKey("agents.id", ondelete="CASCADE"), nullable=False
    )
    policy_id: Mapped[str] = mapped_column(String(36), nullable=False)
    policy_revision_id: Mapped[str] = mapped_column(String(36), nullable=False)
    check_key: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[AlertState] = mapped_column(
        Enum(AlertState, values_callable=lambda enum_type: [item.value for item in enum_type]),
        nullable=False,
    )
    last_result_status: Mapped[CheckResultStatus] = mapped_column(
        Enum(
            CheckResultStatus,
            values_callable=lambda enum_type: [item.value for item in enum_type],
        ),
        nullable=False,
    )
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_occurrence_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_opened_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    opened_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_evaluated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_result_id: Mapped[str | None] = mapped_column(String(36))
    last_value: Mapped[float | None] = mapped_column(Float)
    resolution_reason: Mapped[str | None] = mapped_column(String(64))
    assigned_to_operator_id: Mapped[str | None] = mapped_column(
        ForeignKey("operators.id", ondelete="SET NULL"), index=True
    )
    assigned_to_email: Mapped[str | None] = mapped_column(String(320))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by: Mapped[str | None] = mapped_column(String(320))
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    suppression_window_id: Mapped[str | None] = mapped_column(String(36))
    suppressed_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

    agent: Mapped["Agent"] = relationship()


class AlertEvent(Base):
    """Append-only operational history for one alert lifecycle (#44)."""

    __tablename__ = "alert_events"
    __table_args__ = (
        UniqueConstraint("alert_id", "request_id", name="ux_alert_event_request"),
        UniqueConstraint(
            "alert_id", "source_result_id", name="ux_alert_event_source_result"
        ),
        Index("ix_alert_events_alert_created", "alert_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    alert_id: Mapped[str] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False
    )
    generation: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[AlertEventType] = mapped_column(
        Enum(
            AlertEventType,
            values_callable=lambda enum_type: [item.value for item in enum_type],
        ),
        nullable=False,
    )
    from_state: Mapped[AlertState | None] = mapped_column(
        Enum(
            AlertState,
            values_callable=lambda enum_type: [item.value for item in enum_type],
        )
    )
    to_state: Mapped[AlertState | None] = mapped_column(
        Enum(
            AlertState,
            values_callable=lambda enum_type: [item.value for item in enum_type],
        )
    )
    actor: Mapped[str] = mapped_column(String(320), nullable=False)
    actor_user_id: Mapped[str | None] = mapped_column(String(36))
    comment: Mapped[str | None] = mapped_column(Text)
    comment_redacted: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    assigned_to_operator_id: Mapped[str | None] = mapped_column(String(36))
    assigned_to_email: Mapped[str | None] = mapped_column(String(320))
    source_result_id: Mapped[str | None] = mapped_column(String(36))
    request_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )


class AlertEmailDelivery(Base):
    """One durable, idempotent alert-transition email per recipient (#45)."""

    __tablename__ = "alert_email_deliveries"
    __table_args__ = (
        UniqueConstraint(
            "alert_event_id", "recipient", name="ux_alert_email_event_recipient"
        ),
        Index(
            "ix_alert_email_due", "status", "next_attempt_at", "created_at"
        ),
        Index(
            "ix_alert_email_alert_created", "alert_id", "created_at"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    alert_id: Mapped[str] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False
    )
    alert_event_id: Mapped[str] = mapped_column(
        ForeignKey("alert_events.id", ondelete="CASCADE"), nullable=False
    )
    generation: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[AlertEventType] = mapped_column(
        Enum(
            AlertEventType,
            values_callable=lambda enum_type: [item.value for item in enum_type],
        ),
        nullable=False,
    )
    recipient: Mapped[str] = mapped_column(String(320), nullable=False)
    subject: Mapped[str] = mapped_column(String(500), nullable=False)
    text_body: Mapped[str] = mapped_column(Text, nullable=False)
    html_body: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[EmailDeliveryStatus] = mapped_column(
        Enum(
            EmailDeliveryStatus,
            values_callable=lambda enum_type: [item.value for item in enum_type],
        ),
        nullable=False,
        default=EmailDeliveryStatus.pending,
    )
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    provider_message_id: Mapped[str | None] = mapped_column(String(255))
    last_error_code: Mapped[str | None] = mapped_column(String(100))
    last_retry_request_id: Mapped[str | None] = mapped_column(String(64))
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )


class AlertEmailAttempt(Base):
    """Append-only provider-attempt history without response bodies or secrets."""

    __tablename__ = "alert_email_attempts"
    __table_args__ = (
        UniqueConstraint(
            "delivery_id", "attempt_number", name="ux_alert_email_attempt_number"
        ),
        Index("ix_alert_email_attempt_delivery", "delivery_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    delivery_id: Mapped[str] = mapped_column(
        ForeignKey("alert_email_deliveries.id", ondelete="CASCADE"), nullable=False
    )
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[EmailAttemptStatus] = mapped_column(
        Enum(
            EmailAttemptStatus,
            values_callable=lambda enum_type: [item.value for item in enum_type],
        ),
        nullable=False,
    )
    provider_message_id: Mapped[str | None] = mapped_column(String(255))
    error_code: Mapped[str | None] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ScriptLibraryItem(Base):
    """Stable script identity whose content lives in immutable versions."""

    __tablename__ = "script_library_items"
    __table_args__ = (
        UniqueConstraint("normalized_name", name="ux_script_library_normalized_name"),
        CheckConstraint("latest_version >= 1", name="ck_script_library_latest_version"),
        CheckConstraint("record_version >= 1", name="ck_script_library_record_version"),
        Index("ix_script_library_deprecated_created", "deprecated_at", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    normalized_name: Mapped[str] = mapped_column(String(200), nullable=False)
    latest_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    record_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_by: Mapped[str] = mapped_column(String(320), nullable=False)
    deprecated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deprecated_by: Mapped[str | None] = mapped_column(String(320))
    last_deprecation_request_id: Mapped[str | None] = mapped_column(String(64))
    deprecation_reason_sha256: Mapped[str | None] = mapped_column(String(64))
    deprecation_reason_bytes: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )


class ScriptVersion(Base):
    """Append-only script content and compatibility metadata."""

    __tablename__ = "script_versions"
    __table_args__ = (
        UniqueConstraint("script_id", "version", name="ux_script_version_number"),
        CheckConstraint("version >= 1", name="ck_script_version_number"),
        CheckConstraint(
            "content_bytes BETWEEN 1 AND 57344", name="ck_script_version_content_bytes"
        ),
        CheckConstraint(
            "length(content_sha256) = 64", name="ck_script_version_digest_length"
        ),
        Index("ix_script_version_script_created", "script_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    script_id: Mapped[str] = mapped_column(
        ForeignKey("script_library_items.id", ondelete="RESTRICT"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    language: Mapped[ScriptLanguage] = mapped_column(
        Enum(
            ScriptLanguage,
            values_callable=lambda enum_type: [item.value for item in enum_type],
        ),
        nullable=False,
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    content_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    supported_platforms: Mapped[list] = mapped_column(JSON, nullable=False)
    created_by: Mapped[str] = mapped_column(String(320), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )


class ScriptParameterDefinition(Base):
    """Ordered, immutable validation metadata owned by one script version."""

    __tablename__ = "script_parameter_definitions"
    __table_args__ = (
        UniqueConstraint(
            "script_version_id", "position", name="ux_script_parameter_position"
        ),
        UniqueConstraint(
            "script_version_id", "key", name="ux_script_parameter_key"
        ),
        CheckConstraint("position >= 0", name="ck_script_parameter_position"),
        CheckConstraint(
            "min_length IS NULL OR min_length >= 0",
            name="ck_script_parameter_min_length",
        ),
        CheckConstraint(
            "max_length IS NULL OR max_length >= 1",
            name="ck_script_parameter_max_length",
        ),
        Index("ix_script_parameter_version", "script_version_id", "position"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    script_version_id: Mapped[str] = mapped_column(
        ForeignKey("script_versions.id", ondelete="RESTRICT"), nullable=False
    )
    position: Mapped[int] = mapped_column(Integer, nullable=False)
    key: Mapped[str] = mapped_column(String(64), nullable=False)
    label: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(String(500))
    kind: Mapped[ScriptParameterKind] = mapped_column(
        Enum(
            ScriptParameterKind,
            values_callable=lambda enum_type: [item.value for item in enum_type],
        ),
        nullable=False,
    )
    required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    has_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    default_value: Mapped[object | None] = mapped_column(JSON)
    min_length: Mapped[int | None] = mapped_column(Integer)
    max_length: Mapped[int | None] = mapped_column(Integer)
    minimum: Mapped[float | None] = mapped_column(Float)
    maximum: Mapped[float | None] = mapped_column(Float)
    choices: Mapped[list | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )


class ScriptParameterValueSet(Base):
    """Encrypted, expiring parameter values prepared for one future run."""

    __tablename__ = "script_parameter_value_sets"
    __table_args__ = (
        UniqueConstraint(
            "script_version_id", "request_id", name="ux_script_parameter_set_request"
        ),
        CheckConstraint(
            "length(values_fingerprint) = 64",
            name="ck_script_parameter_set_fingerprint",
        ),
        Index(
            "ix_script_parameter_set_version_created",
            "script_version_id",
            "created_at",
        ),
        Index("ix_script_parameter_set_expiry", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    script_version_id: Mapped[str] = mapped_column(
        ForeignKey("script_versions.id", ondelete="RESTRICT"), nullable=False
    )
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    encrypted_values: Mapped[str] = mapped_column(Text, nullable=False)
    values_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    provided_keys: Mapped[list] = mapped_column(JSON, nullable=False)
    defaulted_keys: Mapped[list] = mapped_column(JSON, nullable=False)
    secret_keys: Mapped[list] = mapped_column(JSON, nullable=False)
    created_by: Mapped[str] = mapped_column(String(320), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ScriptVersionReview(Base):
    """Append-only final review decision for one immutable version."""

    __tablename__ = "script_version_reviews"
    __table_args__ = (
        UniqueConstraint("script_version_id", name="ux_script_version_review_final"),
        Index("ix_script_review_created", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    script_version_id: Mapped[str] = mapped_column(
        ForeignKey("script_versions.id", ondelete="RESTRICT"), nullable=False
    )
    state: Mapped[ScriptReviewState] = mapped_column(
        Enum(
            ScriptReviewState,
            values_callable=lambda enum_type: [item.value for item in enum_type],
        ),
        nullable=False,
    )
    reviewed_by: Mapped[str] = mapped_column(String(320), nullable=False)
    reason_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    reason_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )


class WebhookEndpoint(Base):
    """Operator-managed HTTPS destination for versioned alert events (#46)."""

    __tablename__ = "webhook_endpoints"
    __table_args__ = (
        UniqueConstraint("name", name="ux_webhook_endpoint_name"),
        Index("ix_webhook_endpoint_enabled", "enabled", "deleted_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    event_types: Mapped[list] = mapped_column(JSON, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    current_secret_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_by: Mapped[str] = mapped_column(String(320), nullable=False)
    updated_by: Mapped[str] = mapped_column(String(320), nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )


class WebhookSecretVersion(Base):
    """Encrypted signing secret retained for rotation-safe queued delivery."""

    __tablename__ = "webhook_secret_versions"
    __table_args__ = (
        UniqueConstraint(
            "endpoint_id", "version", name="ux_webhook_secret_endpoint_version"
        ),
        Index("ix_webhook_secret_endpoint", "endpoint_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    endpoint_id: Mapped[str] = mapped_column(
        ForeignKey("webhook_endpoints.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    encrypted_secret: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[str] = mapped_column(String(320), nullable=False)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )


class AlertWebhookDelivery(Base):
    """One idempotent, signed alert event snapshot per webhook endpoint."""

    __tablename__ = "alert_webhook_deliveries"
    __table_args__ = (
        UniqueConstraint(
            "alert_event_id", "endpoint_id", name="ux_alert_webhook_event_endpoint"
        ),
        Index(
            "ix_alert_webhook_due", "status", "next_attempt_at", "created_at"
        ),
        Index(
            "ix_alert_webhook_alert_created", "alert_id", "created_at"
        ),
        Index(
            "ix_alert_webhook_endpoint_created", "endpoint_id", "created_at"
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    endpoint_id: Mapped[str] = mapped_column(
        ForeignKey("webhook_endpoints.id", ondelete="RESTRICT"), nullable=False
    )
    secret_version_id: Mapped[str] = mapped_column(
        ForeignKey("webhook_secret_versions.id", ondelete="RESTRICT"), nullable=False
    )
    alert_id: Mapped[str] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False
    )
    alert_event_id: Mapped[str] = mapped_column(
        ForeignKey("alert_events.id", ondelete="CASCADE"), nullable=False
    )
    generation: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[AlertEventType] = mapped_column(
        Enum(
            AlertEventType,
            values_callable=lambda enum_type: [item.value for item in enum_type],
        ),
        nullable=False,
    )
    destination_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)
    signature_timestamp: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[WebhookDeliveryStatus] = mapped_column(
        Enum(
            WebhookDeliveryStatus,
            values_callable=lambda enum_type: [item.value for item in enum_type],
        ),
        nullable=False,
        default=WebhookDeliveryStatus.pending,
    )
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_http_status: Mapped[int | None] = mapped_column(Integer)
    last_error_code: Mapped[str | None] = mapped_column(String(100))
    last_retry_request_id: Mapped[str | None] = mapped_column(String(64))
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )


class AlertWebhookAttempt(Base):
    """Append-only webhook attempt metadata; response bodies are never stored."""

    __tablename__ = "alert_webhook_attempts"
    __table_args__ = (
        UniqueConstraint(
            "delivery_id", "attempt_number", name="ux_alert_webhook_attempt_number"
        ),
        Index("ix_alert_webhook_attempt_delivery", "delivery_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    delivery_id: Mapped[str] = mapped_column(
        ForeignKey("alert_webhook_deliveries.id", ondelete="CASCADE"),
        nullable=False,
    )
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[WebhookAttemptStatus] = mapped_column(
        Enum(
            WebhookAttemptStatus,
            values_callable=lambda enum_type: [item.value for item in enum_type],
        ),
        nullable=False,
    )
    http_status: Mapped[int | None] = mapped_column(Integer)
    error_code: Mapped[str | None] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AlertObservation(Base):
    """Exactly-once evidence that a check result was considered for an alert.

    The result id is the primary key and cascades with check-result retention,
    keeping this evidence bounded by the existing per-check history policy.
    ``out_of_order`` distinguishes evidence that was counted but correctly did
    not overwrite a newer alert state.
    """

    __tablename__ = "alert_observations"
    __table_args__ = (
        Index("ix_alert_observations_alert_evaluated", "alert_id", "evaluated_at"),
    )

    check_result_id: Mapped[str] = mapped_column(
        ForeignKey("check_results.id", ondelete="CASCADE"), primary_key=True
    )
    alert_id: Mapped[str] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[CheckResultStatus] = mapped_column(
        Enum(
            CheckResultStatus,
            values_callable=lambda enum_type: [item.value for item in enum_type],
        ),
        nullable=False,
    )
    value: Mapped[float | None] = mapped_column(Float)
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    out_of_order: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )


class ScheduledTask(Base):
    """Recurring task schedule targeting an agent or site (issue #49)."""

    __tablename__ = "scheduled_tasks"
    __table_args__ = (
        Index("ix_scheduled_tasks_due", "enabled", "next_run_at"),
        Index("ix_scheduled_tasks_target", "target_type", "target_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    target_type: Mapped[ScheduleTargetType] = mapped_column(
        Enum(
            ScheduleTargetType,
            values_callable=lambda enum_type: [item.value for item in enum_type],
        ),
        nullable=False,
    )
    target_id: Mapped[str] = mapped_column(String(36), nullable=False)
    cron_expression: Mapped[str] = mapped_column(String(100), nullable=False)
    timezone: Mapped[str] = mapped_column(String(100), nullable=False, default="UTC")
    kind: Mapped[CommandKind] = mapped_column(
        Enum(
            CommandKind,
            values_callable=lambda enum_type: [item.value for item in enum_type],
        ),
        nullable=False,
    )
    script_version_id: Mapped[str | None] = mapped_column(
        ForeignKey("script_versions.id", ondelete="SET NULL")
    )
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    concurrency_policy: Mapped[ScheduleConcurrencyPolicy] = mapped_column(
        Enum(
            ScheduleConcurrencyPolicy,
            values_callable=lambda enum_type: [item.value for item in enum_type],
        ),
        nullable=False,
        default=ScheduleConcurrencyPolicy.skip,
    )
    misfire_policy: Mapped[ScheduleMisfirePolicy] = mapped_column(
        Enum(
            ScheduleMisfirePolicy,
            values_callable=lambda enum_type: [item.value for item in enum_type],
        ),
        nullable=False,
        default=ScheduleMisfirePolicy.run_once,
    )
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str | None] = mapped_column(String(50))
    created_by_operator_id: Mapped[str | None] = mapped_column(
        ForeignKey("operators.id", ondelete="SET NULL")
    )
    created_by_email: Mapped[str | None] = mapped_column(String(320))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_now, nullable=False
    )

