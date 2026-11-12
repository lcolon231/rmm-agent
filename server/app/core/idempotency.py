# SPDX-License-Identifier: AGPL-3.0-only
"""Client ``Idempotency-Key`` support for public mutating routes (issue #72).

The contract, per (principal, key):

* **No header** -- behaviour is unchanged; every request is a new attempt.
* **First use** -- the reservation row is written in the *same transaction* as
  the side effect, so a crash or refusal leaves no reservation behind and the
  client may simply retry.
* **Same key, same request, completed** -- the stored status and body are
  replayed (``Idempotent-Replayed: true``); the side effect is not repeated.
* **Same key, different request** -- ``422 idempotency_key_reused``.
* **Same key, still in flight** -- ``409 idempotency_in_progress``; retry.

Reservations expire after ``IDEMPOTENCY_KEY_TTL_HOURS`` and are pruned by the
retention sweeper. A key is scoped to its principal (API token, or operator
for JWT sessions), so two callers can never collide or observe each other.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import api_tokens
from app.core.config import settings
from app.models.models import ApiIdempotencyKey, Operator

HEADER = "Idempotency-Key"
REPLAY_HEADER = "Idempotent-Replayed"
_KEY = re.compile(r"^[\x21-\x7e]{1,128}$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def principal_for(operator: Operator) -> str:
    token = api_tokens.token_principal(operator)
    if token is not None:
        return f"api_token:{token.id}"
    return f"operator:{operator.id}"


def fingerprint(request: Request, body: dict) -> str:
    doc = {
        "method": request.method,
        "path": request.url.path,
        "body": body,
    }
    blob = json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class Idempotency:
    """One request's idempotency state; inert when the client sent no key."""

    def __init__(self, *, key: str | None, principal: str, route: str,
                 method: str, request_sha256: str) -> None:
        self.key = key
        self.principal = principal
        self.route = route
        self.method = method
        self.request_sha256 = request_sha256
        self.record: ApiIdempotencyKey | None = None

    @property
    def enabled(self) -> bool:
        return self.key is not None

    async def replay(self, db: AsyncSession) -> JSONResponse | None:
        """A stored response to replay, ``None`` to proceed, or a refusal."""
        if not self.enabled:
            return None
        existing = (
            await db.execute(
                select(ApiIdempotencyKey).where(
                    ApiIdempotencyKey.principal == self.principal,
                    ApiIdempotencyKey.idempotency_key == self.key,
                )
            )
        ).scalar_one_or_none()
        if existing is None:
            return None
        if _as_utc(existing.expires_at) <= _now():
            await db.delete(existing)
            await db.flush()
            return None
        if existing.request_sha256 != self.request_sha256:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "idempotency_key_reused",
                    "message": "This Idempotency-Key was already used for a different request.",
                },
            )
        if existing.status_code is None or existing.response_json is None:
            raise _in_progress()
        return JSONResponse(
            status_code=existing.status_code,
            content=json.loads(existing.response_json),
            headers={REPLAY_HEADER: "true"},
        )

    async def reserve(self, db: AsyncSession) -> None:
        """Claim the key inside the caller's transaction, before the side effect."""
        if not self.enabled:
            return
        now = _now()
        record = ApiIdempotencyKey(
            principal=self.principal,
            idempotency_key=self.key,
            method=self.method,
            route=self.route,
            request_sha256=self.request_sha256,
            created_at=now,
            expires_at=now + timedelta(hours=settings.idempotency_key_ttl_hours),
        )
        try:
            async with db.begin_nested():
                db.add(record)
                await db.flush()
        except IntegrityError as exc:
            # A concurrent request with the same key won the reservation.
            raise _in_progress() from exc
        self.record = record

    async def complete(self, db: AsyncSession, status_code: int, body: str) -> None:
        if self.record is None:
            return
        self.record.status_code = status_code
        self.record.response_json = body
        await db.flush()


def _in_progress() -> HTTPException:
    return HTTPException(
        status_code=409,
        detail={
            "code": "idempotency_in_progress",
            "message": "A request with this Idempotency-Key is still being processed; retry.",
        },
    )


def for_request(
    request: Request, operator: Operator, key: str | None, body: dict
) -> Idempotency:
    if key is not None and not _KEY.fullmatch(key):
        raise HTTPException(
            status_code=400,
            detail={
                "code": "idempotency_key_invalid",
                "message": "Idempotency-Key must be 1-128 printable ASCII characters.",
            },
        )
    route = getattr(request.scope.get("route"), "path", request.url.path)
    return Idempotency(
        key=key,
        principal=principal_for(operator),
        route=route,
        method=request.method,
        request_sha256=fingerprint(request, body),
    )


async def prune_expired(db: AsyncSession, now: datetime | None = None) -> int:
    result = await db.execute(
        delete(ApiIdempotencyKey).where(ApiIdempotencyKey.expires_at <= (now or _now()))
    )
    return result.rowcount or 0
