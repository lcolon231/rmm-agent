"""NodeLink RMM — FastAPI application entry point."""
from __future__ import annotations

# SPDX-License-Identifier: AGPL-3.0-only

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api import agents, auth, management
from app.core.config import settings
from app.core.database import Base, engine
from app.core.prodcheck import ensure_safe_production_config
from app.core.schema_revision import ensure_schema_current
from app.core.tasks import anchor_publisher, offline_sweeper


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
    try:
        yield
    finally:
        stop.set()
        await asyncio.gather(sweeper, publisher)


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(auth.router, prefix="/api/v1")
app.include_router(agents.router, prefix="/api/v1")
app.include_router(management.router, prefix="/api/v1")


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "app": settings.app_name}
