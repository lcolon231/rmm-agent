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
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core import anchor, audit
from app.core.command_envelope import COMMAND_ENVELOPE_V1, canonical_command_bytes
from app.core.database import get_db
from app.core.security import generate_token, hash_token, sign_command
from app.models.models import (
    Agent,
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
# Commands
# --------------------------------------------------------------------------- #
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
    if COMMAND_ENVELOPE_V1 not in (agent.command_envelope_versions or []):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "agent_command_envelope_version_unsupported",
                "required": COMMAND_ENVELOPE_V1,
                "agent_supported": agent.command_envelope_versions or [],
            },
        )

    now = _now()
    cmd = Command(
        id=str(uuid.uuid4()),
        agent_id=agent_id,
        kind=body.kind,
        payload=body.payload,
        envelope_version=COMMAND_ENVELOPE_V1,
        status=CommandStatus.queued,
        created_at=now,
        expires_at=now + timedelta(seconds=body.ttl_seconds),
    )
    db.add(cmd)
    await db.flush()  # persist before signing

    cmd.signature = sign_command(
        envelope_version=cmd.envelope_version,
        command_id=cmd.id,
        agent_id=agent_id,
        kind=body.kind.value,
        payload=body.payload,
    )
    envelope_sha256 = hashlib.sha256(
        canonical_command_bytes(
            cmd.envelope_version,
            cmd.id,
            agent_id,
            body.kind.value,
            body.payload,
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
