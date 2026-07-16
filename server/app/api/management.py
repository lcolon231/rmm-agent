"""Operator-facing endpoints: manage clients, sites, enrollment tokens, view
agents, and dispatch commands.

Authorization model:
  - The whole router requires a valid operator token (readonly or higher). This
    is set as a router-level dependency, so no route is reachable anonymously.
  - Mutating routes (provisioning, dispatch) additionally require `operator` or
    higher, declared per-route with Depends(require_role(...)).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core import audit
from app.core.database import get_db
from app.core.security import generate_token, hash_token, sign_command
from app.models.models import (
    Agent,
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

    now = _now()
    cmd = Command(
        id=str(uuid.uuid4()),
        agent_id=agent_id,
        kind=body.kind,
        payload=body.payload,
        status=CommandStatus.queued,
        created_at=now,
        expires_at=now + timedelta(seconds=body.ttl_seconds),
    )
    db.add(cmd)
    await db.flush()  # persist before signing

    cmd.signature = sign_command(
        command_id=cmd.id,
        agent_id=agent_id,
        kind=body.kind.value,
        payload=body.payload,
    )

    await audit.record(
        db,
        action="command.dispatched",
        actor=operator.email,
        agent_id=agent_id,
        detail={"command_id": cmd.id, "kind": body.kind.value, "payload": body.payload},
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
