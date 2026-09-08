# SPDX-License-Identifier: AGPL-3.0-only
"""Authenticated assistant routes. Endpoint actions are deliberately absent."""
from uuid import UUID
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_operator
from app.core.assistant import policy, service
from app.core.assistant.provider import get_provider
from app.core.database import get_db
from app.models.models import AssistantConversation, Operator
from app.schemas.assistant import ConversationCreate, RunCreate


def no_cache(response: Response):
    response.headers["Cache-Control"] = "no-store"


router = APIRouter(prefix="/assistant", tags=["assistant"],
    dependencies=[Depends(get_current_operator), Depends(no_cache)])


async def read_body(request, model):
    content = bytearray()
    async for chunk in request.stream():
        content.extend(chunk)
        if len(content) > 20000:
            raise HTTPException(413, detail={"code": "assistant_input_limit"})
    try:
        return model.model_validate_json(content)
    except (ValidationError, ValueError):
        # Default validation responses can echo input. Assistant bodies never do.
        raise HTTPException(422, detail={"code": "assistant_invalid_input"}) from None


@router.get("/status")
async def status(operator: Operator = Depends(get_current_operator)):
    return {"state": policy.availability(operator), "read_only": True, "retention_days": policy.RETENTION_DAYS}


@router.get("/conversations")
async def conversations(client_id: UUID, authorization: str = Header(), db: AsyncSession = Depends(get_db)):
    operator, _ = await policy.authorize(db, authorization, client_id=str(client_id))
    rows = (await db.execute(select(AssistantConversation).where(
        AssistantConversation.operator_id == operator.id, AssistantConversation.client_id == str(client_id),
        AssistantConversation.expires_at > policy.now()).order_by(AssistantConversation.created_at.desc()).limit(20))).scalars().all()
    return {"items": [{"id": row.id, "created_at": row.created_at, "expires_at": row.expires_at} for row in rows]}


@router.post("/conversations", status_code=201)
async def create(request: Request, authorization: str = Header(), db: AsyncSession = Depends(get_db)):
    body = await read_body(request, ConversationCreate)
    row = await service.create_conversation(db, authorization, str(body.client_id))
    return {"id": row.id, "client_id": row.client_id, "expires_at": row.expires_at, "runs": []}


@router.get("/conversations/{conversation_id}")
async def history(conversation_id: UUID, authorization: str = Header(), db: AsyncSession = Depends(get_db)):
    return await service.history(db, authorization, str(conversation_id))


@router.post("/conversations/{conversation_id}/runs")
async def run(conversation_id: UUID, request: Request, authorization: str = Header(),
              db: AsyncSession = Depends(get_db), provider=Depends(get_provider)):
    body = await read_body(request, RunCreate)
    run_id, created = await service.reserve(db, authorization, str(conversation_id), body)
    if created:
        await service.run(db, authorization, str(conversation_id), run_id, provider)
    return await service.history(db, authorization, str(conversation_id))


@router.post("/conversations/{conversation_id}/runs/{request_id}/cancel")
async def cancel(conversation_id: UUID, request_id: UUID, authorization: str = Header(), db: AsyncSession = Depends(get_db)):
    return await service.cancel(db, authorization, str(conversation_id), str(request_id))
