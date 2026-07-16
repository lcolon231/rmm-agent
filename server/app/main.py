"""NodeLink RMM — FastAPI application entry point."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api import agents, auth, management
from app.core.config import settings
from app.core.database import Base, engine
from app.core.tasks import offline_sweeper


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Dev convenience: create tables on startup. In production use Alembic
    # migrations instead (see alembic/).
    if settings.debug:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    stop = asyncio.Event()
    sweeper = asyncio.create_task(offline_sweeper(stop))
    try:
        yield
    finally:
        stop.set()
        await sweeper


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
