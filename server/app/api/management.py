# SPDX-License-Identifier: AGPL-3.0-only
"""Operator-facing endpoints: manage clients, sites, enrollment tokens, view
agents, and dispatch commands.

Authorization model:
  - The whole router requires a valid operator token (readonly or higher). This
    is set as a router-level dependency, so no route is reachable anonymously.
  - Mutating routes (provisioning, dispatch) additionally require `operator` or
    higher, declared per-route with Depends(require_role(...)).
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core import anchor, audit
from app.core.command_envelope import (
    ACTIVE_COMMAND_ENVELOPE_VERSION,
    COMMAND_ENVELOPE_V3,
    COMMAND_SCHEMA_VERSION,
    canonical_command_bytes,
    format_command_time,
    select_command_envelope_version,
)
from app.core.config import settings
from app.core.database import get_db
from app.core.security import generate_token, hash_token, sign_command
from app.core.keyring import active_signing_key, load_keyring
from app.models.models import (
    Agent,
    AgentTrustState,
    AuditAnchor,
    Client,
    Command,
    CommandStatus,
    EnrollmentToken,
    Operator,
    OperatorRole,
    Site,
)
from app.schemas.schemas import (
    AgentOut,
    AnchorOut,
    AnchorVerifyOut,
    ClientCreate,
    ClientOut,
    CommandCreate,
    CommandOut,
    EnrollmentTokenCreate,
    EnrollmentTokenOut,
    SiteCreate,
    SiteOut,
    TrustStateChange,
)

# Router-level dependency: every route here needs at least a readonly operator.
router = APIRouter(
    tags=["management"],
    dependencies=[Depends(require_role(OperatorRole.readonly))],
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Clients & sites
# --------------------------------------------------------------------------- #
@router.post("/clients", response_model=ClientOut)
async def create_client(
    body: ClientCreate,
    _op: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    client = Client(name=body.name)
    db.add(client)
    await db.flush()
    return client


@router.get("/clients", response_model=list[ClientOut])
async def list_clients(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Client).order_by(Client.created_at))
    return list(result.scalars().all())


@router.post("/sites", response_model=SiteOut)
async def create_site(
    body: SiteCreate,
    _op: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    if not await db.get(Client, body.client_id):
        raise HTTPException(status_code=404, detail="Client not found")
    site = Site(client_id=body.client_id, name=body.name)
    db.add(site)
    await db.flush()
    return site


# --------------------------------------------------------------------------- #
# Enrollment tokens
# --------------------------------------------------------------------------- #
@router.post("/enrollment-tokens", response_model=EnrollmentTokenOut)
async def create_enrollment_token(
    body: EnrollmentTokenCreate,
    _op: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    if not await db.get(Site, body.site_id):
        raise HTTPException(status_code=404, detail="Site not found")

    plaintext = generate_token()
    etoken = EnrollmentToken(
        site_id=body.site_id,
        token_hash=hash_token(plaintext),
        label=body.label,
        max_uses=body.max_uses,
        expires_at=body.expires_at,
    )
    db.add(etoken)
    await db.flush()

    return EnrollmentTokenOut(
        id=etoken.id,
        site_id=etoken.site_id,
        token=plaintext,
        label=etoken.label,
        max_uses=etoken.max_uses,
        expires_at=etoken.expires_at,
    )


# --------------------------------------------------------------------------- #
# Agents
# --------------------------------------------------------------------------- #
@router.get("/agents", response_model=list[AgentOut])
async def list_agents(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Agent).order_by(Agent.enrolled_at))
    return list(result.scalars().all())


@router.get("/agents/{agent_id}", response_model=AgentOut)
async def get_agent(agent_id: str, db: AsyncSession = Depends(get_db)):
    agent = await db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


# --------------------------------------------------------------------------- #
# Agent trust state
# --------------------------------------------------------------------------- #
def _trust_conflict(agent: Agent, wanted: str) -> HTTPException:
    return HTTPException(
        status_code=409,
        detail={
            "code": "agent_trust_state_conflict",
            "current": agent.trust_state.value,
            "requested": wanted,
        },
    )


async def _apply_trust_change(
    db: AsyncSession,
    agent: Agent,
    new_state: AgentTrustState,
    reason: str,
    operator: Operator,
    action: str,
) -> Agent:
    previous = agent.trust_state
    agent.trust_state = new_state
    agent.trust_state_reason = reason
    agent.trust_state_changed_at = _now()
    agent.trust_state_changed_by = operator.email
    await audit.record(
        db,
        action=action,
        actor=operator.email,
        agent_id=agent.id,
        detail={
            "previous_trust_state": previous.value,
            "trust_state": new_state.value,
            "reason": reason,
        },
    )
    return agent


@router.post("/agents/{agent_id}/quarantine", response_model=AgentOut)
async def quarantine_agent(
    agent_id: str,
    body: TrustStateChange,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    """Suspend trust in an agent without destroying its identity.

    A quarantined agent still authenticates and checks in (so the operator can
    see it is alive), but receives no commands, may not submit results, and has
    no telemetry or inventory recorded. Reversible via restore.
    """
    agent = await db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.trust_state != AgentTrustState.active:
        raise _trust_conflict(agent, AgentTrustState.quarantined.value)
    return await _apply_trust_change(
        db, agent, AgentTrustState.quarantined, body.reason, operator, "agent.quarantined"
    )


@router.post("/agents/{agent_id}/restore", response_model=AgentOut)
async def restore_agent(
    agent_id: str,
    body: TrustStateChange,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    """Return a quarantined agent to active. Revoked agents cannot be restored —
    revocation is terminal and the endpoint must re-enroll as a new identity."""
    agent = await db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.trust_state != AgentTrustState.quarantined:
        raise _trust_conflict(agent, AgentTrustState.active.value)
    return await _apply_trust_change(
        db, agent, AgentTrustState.active, body.reason, operator, "agent.restored"
    )


@router.post("/agents/{agent_id}/revoke", response_model=AgentOut)
async def revoke_agent(
    agent_id: str,
    body: TrustStateChange,
    operator: Operator = Depends(require_role(OperatorRole.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Permanently revoke an agent's credentials (admin only — irreversible).

    The agent's bearer token stops authenticating entirely, and any still-queued
    or dispatched-but-unreported commands are expired so nothing issued under
    the old trust can be delivered or complete later.
    """
    agent = await db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.trust_state == AgentTrustState.revoked:
        raise _trust_conflict(agent, AgentTrustState.revoked.value)

    result = await db.execute(
        select(Command).where(
            Command.agent_id == agent.id,
            Command.status.in_([CommandStatus.queued, CommandStatus.dispatched]),
        )
    )
    expired_ids = []
    for cmd in result.scalars().all():
        cmd.status = CommandStatus.expired
        expired_ids.append(cmd.id)

    agent = await _apply_trust_change(
        db, agent, AgentTrustState.revoked, body.reason, operator, "agent.revoked"
    )
    if expired_ids:
        await audit.record(
            db,
            action="agent.commands_expired_on_revoke",
            actor=operator.email,
            agent_id=agent.id,
            detail={"command_ids": sorted(expired_ids)},
        )
    return agent


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
@router.get("/signing-keys")
async def list_signing_keys(db: AsyncSession = Depends(get_db)):
    """Expose redacted key lifecycle state for operator verification."""
    active_id, keys = load_keyring()
    return {
        "active_key_id": active_id,
        "keys": [
            {"key_id": key_id, "status": key.status, "active": key_id == active_id}
            for key_id, key in sorted(keys.items())
        ],
    }


@router.post("/agents/{agent_id}/commands", response_model=CommandOut)
async def dispatch_command(
    agent_id: str,
    body: CommandCreate,
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    """Queue a command for an agent, signed so the agent can verify authenticity.

    The acting operator is recorded in the audit event, so the tamper-evident
    log answers not just *what* ran but *who* ordered it.
    """
    agent = await db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    # Trust gate before capability negotiation: no new work may even be queued
    # for an agent the server no longer fully trusts.
    if agent.trust_state != AgentTrustState.active:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "agent_not_trusted",
                "trust_state": agent.trust_state.value,
            },
        )
    # Admission control: cap the outstanding (non-terminal) work per agent so a
    # runaway operator or client cannot pile unbounded commands on one
    # endpoint. Terminal commands (succeeded/failed/expired) do not count.
    outstanding = (
        await db.execute(
            select(func.count())
            .select_from(Command)
            .where(
                Command.agent_id == agent_id,
                Command.status.in_(
                    [
                        CommandStatus.queued,
                        CommandStatus.dispatched,
                        CommandStatus.running,
                    ]
                ),
            )
        )
    ).scalar_one()
    if outstanding >= settings.max_outstanding_commands_per_agent:
        raise HTTPException(
            status_code=429,
            detail={
                "code": "agent_command_queue_full",
                "outstanding": outstanding,
                "limit": settings.max_outstanding_commands_per_agent,
            },
        )
    envelope_version = select_command_envelope_version(
        agent.command_envelope_versions or []
    )
    if envelope_version is None:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "agent_command_envelope_version_unsupported",
                "required": ACTIVE_COMMAND_ENVELOPE_VERSION,
                "agent_supported": agent.command_envelope_versions or [],
            },
        )

    now = _now()
    key_id = active_signing_key().key_id if envelope_version == COMMAND_ENVELOPE_V3 else None
    cmd = Command(
        id=str(uuid.uuid4()),
        agent_id=agent_id,
        kind=body.kind,
        payload=body.payload,
        envelope_version=envelope_version,
        schema_version=COMMAND_SCHEMA_VERSION,
        issued_at=now,
        nonce=generate_token(24),
        signing_key_id=key_id,
        status=CommandStatus.queued,
        created_at=now,
        expires_at=now + timedelta(seconds=body.ttl_seconds),
    )
    db.add(cmd)
    await db.flush()  # persist before signing

    cmd.signature = sign_command(
        envelope_version=cmd.envelope_version,
        schema_version=cmd.schema_version,
        command_id=cmd.id,
        agent_id=agent_id,
        kind=body.kind.value,
        payload=body.payload,
        issued_at=format_command_time(cmd.issued_at),
        expires_at=format_command_time(cmd.expires_at),
        nonce=cmd.nonce,
        signing_key_id=cmd.signing_key_id,
    )
    envelope_sha256 = hashlib.sha256(
        canonical_command_bytes(
            cmd.envelope_version,
            cmd.schema_version,
            cmd.id,
            agent_id,
            body.kind.value,
            body.payload,
            format_command_time(cmd.issued_at),
            format_command_time(cmd.expires_at),
            cmd.nonce,
            cmd.signing_key_id,
        )
    ).hexdigest()

    await audit.record(
        db,
        action="command.dispatched",
        actor=operator.email,
        agent_id=agent_id,
        detail={
            "command_id": cmd.id,
            "kind": body.kind.value,
            "payload_keys": sorted(body.payload),
            "envelope_version": cmd.envelope_version,
            "schema_version": cmd.schema_version,
            "issued_at": format_command_time(cmd.issued_at),
            "expires_at": format_command_time(cmd.expires_at),
            "nonce": cmd.nonce,
            "signing_key_id": cmd.signing_key_id,
            "envelope_sha256": envelope_sha256,
        },
    )
    return cmd


@router.get("/agents/{agent_id}/commands", response_model=list[CommandOut])
async def list_commands(agent_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Command)
        .where(Command.agent_id == agent_id)
        .order_by(Command.created_at.desc())
    )
    return list(result.scalars().all())


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #
@router.get("/audit/verify")
async def verify_audit_chain(db: AsyncSession = Depends(get_db)):
    ok, broken_at = await audit.verify_chain(db)
    return {"intact": ok, "first_broken_event_id": broken_at}


@router.post("/audit/anchors", response_model=AnchorOut)
async def create_audit_anchor(
    operator: Operator = Depends(require_role(OperatorRole.operator)),
    db: AsyncSession = Depends(get_db),
):
    """Commit to the audit chain as it stands: compute the Merkle root over all
    event hashes and store it as an anchor.

    The returned `merkle_root` is the value to publish OUTSIDE this system
    (transparency log, on-chain, the monthly compliance report). The anchor row
    alone proves nothing against an attacker with database access — the
    external copies are what make history un-rewritable.
    """
    result = await anchor.create_anchor(db)
    if result is None:
        raise HTTPException(status_code=400, detail="No audit events to anchor")

    await audit.record(
        db,
        action="audit.anchored",
        actor=operator.email,
        detail={
            "anchor_id": result.id,
            "merkle_root": result.merkle_root,
            "event_count": result.event_count,
        },
    )
    return result


@router.get("/audit/anchors", response_model=list[AnchorOut])
async def list_audit_anchors(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AuditAnchor).order_by(AuditAnchor.created_at))
    return list(result.scalars().all())


@router.get("/audit/anchors/{anchor_id}/verify", response_model=AnchorVerifyOut)
async def verify_audit_anchor(anchor_id: str, db: AsyncSession = Depends(get_db)):
    """Recompute the Merkle root over the anchor's covered prefix and compare.
    A mismatch means events covered by the anchor were altered, removed, or
    reordered after it was made."""
    a = await db.get(AuditAnchor, anchor_id)
    if a is None:
        raise HTTPException(status_code=404, detail="Anchor not found")
    ok, reason = await anchor.verify_anchor(db, a)
    return AnchorVerifyOut(anchor_id=a.id, intact=ok, reason=reason)
