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
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    JSON,
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


class CommandKind(str, enum.Enum):
    powershell = "powershell"
    shell = "shell"
    collect_inventory = "collect_inventory"


class CommandStatus(str, enum.Enum):
    queued = "queued"
    dispatched = "dispatched"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    expired = "expired"


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
    label: Mapped[str | None] = mapped_column(String(200))
    max_uses: Mapped[int] = mapped_column(Integer, default=1)
    uses: Mapped[int] = mapped_column(Integer, default=0)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    site: Mapped["Site"] = relationship(back_populates="enrollment_tokens")

    @property
    def is_usable(self) -> bool:
        if self.revoked or self.uses >= self.max_uses:
            return False
        if self.expires_at is not None:
            exp = self.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp < datetime.now(timezone.utc):
                return False
        return True


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    site_id: Mapped[str] = mapped_column(
        ForeignKey("sites.id", ondelete="CASCADE"), nullable=False
    )
    # SHA-256 of the agent's long-lived bearer token.
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    hostname: Mapped[str] = mapped_column(String(255), default="")
    os: Mapped[str] = mapped_column(String(100), default="")
    os_version: Mapped[str] = mapped_column(String(100), default="")
    agent_version: Mapped[str] = mapped_column(String(50), default="")
    # Versions this agent most recently advertised. Empty means commands fail
    # closed until a compatible agent checks in.
    command_envelope_versions: Mapped[list[str]] = mapped_column(
        JSON, default=list, nullable=False
    )

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

    # Latest inventory snapshot (hardware + installed software), stored as JSON.
    inventory: Mapped[dict | None] = mapped_column(JSON)

    site: Mapped["Site"] = relationship(back_populates="agents")
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
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    agent: Mapped["Agent"] = relationship(back_populates="commands")


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
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    agent_id: Mapped[str | None] = mapped_column(String(36), index=True)
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
    # How many events (in (ts, id) order from the start of the chain) this
    # anchor covers, and the last covered event for a cheap consistency check.
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    last_event_id: Mapped[str] = mapped_column(String(36), nullable=False)
    merkle_root: Mapped[str] = mapped_column(String(64), nullable=False)
