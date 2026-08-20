"""NodeLink RMM — FastAPI application entry point."""
from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-only

import asyncio
import logging
from time import perf_counter
from uuid import uuid4
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import func, select, text

from app.api import (
    agent_updates,
    agents,
    auth,
    evidence,
    management,
    meshcentral,
    scheduled_tasks,
    script_library,
    shell_sessions,
)
from app.core import metrics
from app.core.config import settings
from app.core.database import AsyncSessionLocal, Base, engine
from app.core.prodcheck import ensure_safe_production_config
from app.core.schema_revision import ensure_schema_current
from app.core.structured_logging import log_event
from app.core.tasks import (
    anchor_publisher,
    email_alert_sender,
    offline_sweeper,
    retention_sweeper,
    scheduled_task_dispatcher,
    shell_session_sweeper,
    webhook_sender,
)
from app.models.models import Agent


logger = logging.getLogger("nodelink.http")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail closed before touching anything else: a production deployment with
    # debug mode, placeholder secrets, missing signing keys, or a non-HTTPS
    # public URL must not serve a single request.
    ensure_safe_production_config(settings)

    # Dev convenience: create tables on startup. In production use Alembic
    # migrations instead (see alembic/).
    if settings.debug:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    else:
        # Production and production-like starts fail closed when the database
        # is unversioned, behind, or ahead of this server build.
        await ensure_schema_current(engine)

    stop = asyncio.Event()
    sweeper = asyncio.create_task(offline_sweeper(stop))
    publisher = asyncio.create_task(anchor_publisher(stop))
    pruner = asyncio.create_task(retention_sweeper(stop))
    email_sender = asyncio.create_task(email_alert_sender(stop))
    webhook_delivery_sender = asyncio.create_task(webhook_sender(stop))
    task_scheduler = asyncio.create_task(scheduled_task_dispatcher(stop))
    shell_expirer = asyncio.create_task(shell_session_sweeper(stop))
    try:
        yield
    finally:
        stop.set()
        await asyncio.gather(
            sweeper,
            publisher,
            pruner,
            email_sender,
            webhook_delivery_sender,
            task_scheduler,
            shell_expirer,
        )


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(auth.router, prefix="/api/v1")
app.include_router(agents.router, prefix="/api/v1")
app.include_router(evidence.router, prefix="/api/v1")
app.include_router(management.router, prefix="/api/v1")
app.include_router(script_library.router, prefix="/api/v1")
app.include_router(scheduled_tasks.router, prefix="/api/v1")
app.include_router(shell_sessions.router, prefix="/api/v1")
app.include_router(shell_sessions.agent_router, prefix="/api/v1")
app.include_router(meshcentral.router, prefix="/api/v1")
app.include_router(agent_updates.router, prefix="/api/v1")
app.include_router(agent_updates.agent_router, prefix="/api/v1")



@app.middleware("http")
async def log_request(request: Request, call_next):
    """Log request metadata without reading headers, queries, or bodies."""
    started = perf_counter()
    request_id = uuid4().hex
    response_status = 500
    try:
        response = await call_next(request)
        response_status = response.status_code
        response.headers["X-Request-ID"] = request_id
        return response
    finally:
        log_event(
            logger,
            "http.request",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            status=response_status,
            duration_ms=round((perf_counter() - started) * 1000, 2),
            source_ip=request.client.host if request.client else None,
        )


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "app": settings.app_name}


@app.get("/readyz")
async def readyz():
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Database is unavailable") from exc
    return {"status": "ready", "app": settings.app_name}


@app.get("/metrics", response_class=PlainTextResponse)
async def enrollment_metrics():
    async with AsyncSessionLocal() as db:
        rows = (
            await db.execute(
                select(Agent.status, func.count(Agent.id)).group_by(Agent.status)
            )
        ).all()
    statuses = {
        status.value if hasattr(status, "value") else str(status): count
        for status, count in rows
    }
    return metrics.prometheus_text(statuses)
