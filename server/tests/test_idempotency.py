# SPDX-License-Identifier: AGPL-3.0-only
"""Client Idempotency-Key semantics on public command dispatch (issue #72).

A retried dispatch must never queue a second signed command, a reused key
must never silently apply a different request, and a refused request must
never strand a reservation that would block the client's honest retry.
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_idempotency.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

from datetime import datetime, timedelta, timezone  # noqa: E402

import pytest  # noqa: E402
from sqlalchemy import func, select  # noqa: E402

from app.core import idempotency  # noqa: E402
from app.core.database import AsyncSessionLocal  # noqa: E402
from app.models.models import ApiIdempotencyKey, Command  # noqa: E402
from tests.test_api_tokens import _bearer, _mint, env  # noqa: E402,F401  (fixture)

pytestmark = pytest.mark.asyncio

BODY = {"kind": "scan_updates", "payload": {}}


async def _operator_token(http, ids, sessions) -> dict:
    return _bearer(await _mint(
        http, sessions["owner"], ids["client_a"],
        role_ceiling="operator", client_role_ceiling="client_operator",
    ))


async def _counts() -> tuple[int, int]:
    async with AsyncSessionLocal() as db:
        commands = (await db.execute(select(func.count()).select_from(Command))).scalar_one()
        keys = (await db.execute(select(func.count()).select_from(ApiIdempotencyKey))).scalar_one()
    return commands, keys


async def test_retry_with_same_key_replays_without_a_second_command(env):  # noqa: F811
    http, ids, sessions = env
    token = await _operator_token(http, ids, sessions)
    headers = {**token, "Idempotency-Key": "retry-1"}
    first = await http.post(f"/agents/{ids['agent_a']}/commands", json=BODY, headers=headers)
    assert first.status_code == 200, first.text
    assert "Idempotent-Replayed" not in first.headers
    second = await http.post(f"/agents/{ids['agent_a']}/commands", json=BODY, headers=headers)
    assert second.status_code == 200
    assert second.headers["Idempotent-Replayed"] == "true"
    assert second.json() == first.json()
    assert await _counts() == (1, 1)


async def test_same_key_different_request_is_refused(env):  # noqa: F811
    http, ids, sessions = env
    token = await _operator_token(http, ids, sessions)
    headers = {**token, "Idempotency-Key": "reuse-1"}
    assert (await http.post(f"/agents/{ids['agent_a']}/commands", json=BODY, headers=headers)).status_code == 200
    other = await http.post(
        f"/agents/{ids['agent_a']}/commands",
        json={**BODY, "ttl_seconds": 600},
        headers=headers,
    )
    assert other.status_code == 422
    assert other.json()["detail"]["code"] == "idempotency_key_reused"
    assert await _counts() == (1, 1)


async def test_in_flight_key_is_409(env):  # noqa: F811
    http, ids, sessions = env
    token = await _operator_token(http, ids, sessions)
    headers = {**token, "Idempotency-Key": "busy-1"}
    assert (await http.post(f"/agents/{ids['agent_a']}/commands", json=BODY, headers=headers)).status_code == 200
    # Rewind the reservation to its pre-completion state: a concurrent first
    # request that has claimed the key but not yet committed its response.
    async with AsyncSessionLocal() as db:
        row = (await db.execute(select(ApiIdempotencyKey))).scalar_one()
        row.status_code = None
        row.response_json = None
        await db.commit()
    busy = await http.post(f"/agents/{ids['agent_a']}/commands", json=BODY, headers=headers)
    assert busy.status_code == 409, busy.text
    assert busy.json()["detail"]["code"] == "idempotency_in_progress"
    assert await _counts() == (1, 1)


async def test_keys_are_scoped_per_principal(env):  # noqa: F811
    http, ids, sessions = env
    token = await _operator_token(http, ids, sessions)
    via_token = await http.post(
        f"/agents/{ids['agent_a']}/commands", json=BODY,
        headers={**token, "Idempotency-Key": "shared-key"},
    )
    via_session = await http.post(
        f"/agents/{ids['agent_a']}/commands", json=BODY,
        headers={**sessions["owner"], "Idempotency-Key": "shared-key"},
    )
    assert via_token.status_code == via_session.status_code == 200
    assert via_token.json()["id"] != via_session.json()["id"]
    assert await _counts() == (2, 2)


async def test_no_key_keeps_existing_behaviour(env):  # noqa: F811
    http, ids, sessions = env
    token = await _operator_token(http, ids, sessions)
    for _ in range(2):
        assert (await http.post(f"/agents/{ids['agent_a']}/commands", json=BODY, headers=token)).status_code == 200
    assert await _counts() == (2, 0)


async def test_malformed_key_is_400(env):  # noqa: F811
    http, ids, sessions = env
    token = await _operator_token(http, ids, sessions)
    for key in ("has space", "x" * 129):
        resp = await http.post(
            f"/agents/{ids['agent_a']}/commands", json=BODY,
            headers={**token, "Idempotency-Key": key},
        )
        assert resp.status_code == 400
        assert resp.json()["detail"]["code"] == "idempotency_key_invalid"


async def test_refusals_never_strand_a_reservation(env):  # noqa: F811
    http, ids, sessions = env
    readonly = _bearer(await _mint(http, sessions["owner"], ids["client_a"]))
    denied = await http.post(
        f"/agents/{ids['agent_a']}/commands", json=BODY,
        headers={**readonly, "Idempotency-Key": "refused-1"},
    )
    assert denied.status_code == 403
    cross = await http.post(
        f"/agents/{ids['agent_b']}/commands", json=BODY,
        headers={**readonly, "Idempotency-Key": "refused-2"},
    )
    assert cross.status_code == 404
    assert await _counts() == (0, 0)


async def test_expired_reservation_is_forgotten_and_pruned(env):  # noqa: F811
    http, ids, sessions = env
    token = await _operator_token(http, ids, sessions)
    headers = {**token, "Idempotency-Key": "old-1"}
    first = await http.post(f"/agents/{ids['agent_a']}/commands", json=BODY, headers=headers)
    async with AsyncSessionLocal() as db:
        row = (await db.execute(select(ApiIdempotencyKey))).scalar_one()
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await db.commit()
    again = await http.post(f"/agents/{ids['agent_a']}/commands", json=BODY, headers=headers)
    assert again.status_code == 200
    assert "Idempotent-Replayed" not in again.headers
    assert again.json()["id"] != first.json()["id"]
    assert await _counts() == (2, 1)

    async with AsyncSessionLocal() as db:
        row = (await db.execute(select(ApiIdempotencyKey))).scalar_one()
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await db.commit()
        assert await idempotency.prune_expired(db) == 1
        await db.commit()
    assert await _counts() == (2, 0)


async def test_concurrent_reservation_loser_gets_409(env):  # noqa: F811
    """The unique (principal, key) index decides a same-key race."""
    from fastapi import HTTPException

    _http, _ids, _sessions = env
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        db.add(ApiIdempotencyKey(
            principal="operator:x", idempotency_key="race-1", method="POST",
            route="/r", request_sha256="0" * 64, created_at=now,
            expires_at=now + timedelta(hours=1),
        ))
        await db.commit()
    async with AsyncSessionLocal() as db:
        loser = idempotency.Idempotency(
            key="race-1", principal="operator:x", route="/r", method="POST",
            request_sha256="0" * 64,
        )
        with pytest.raises(HTTPException) as refused:
            await loser.reserve(db)
        assert refused.value.status_code == 409
        assert refused.value.detail["code"] == "idempotency_in_progress"
