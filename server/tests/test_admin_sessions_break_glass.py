# SPDX-License-Identifier: AGPL-3.0-only
"""Administrative session management and break-glass access (issue #69).

Two capabilities, tested against the properties that justify them rather than
against their happy paths: that a revoked session dies on the *next* request,
that neither ceiling can be evaded by staying active or by refreshing, and that
emergency access is loud, bounded, and unable to entrench itself.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_admin_sessions.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core import break_glass as bg  # noqa: E402
from app.core import sessions as sessions_core  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import (  # noqa: E402
    AMR_BREAK_GLASS,
    create_access_token,
    decode_access_token,
    hash_password,
)
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    AuditEvent,
    BreakGlassAccount,
    BreakGlassActivation,
    Operator,
    OperatorRole,
    OperatorSession,
)

ADMIN_EMAIL = "platform-admin@nodelink.test"
ADMIN_PASSWORD = "correct-horse-battery"
SECOND_EMAIL = "second-admin@nodelink.test"
VIEWER_EMAIL = "viewer@nodelink.test"
VIEWER_PASSWORD = "read-only-pass"


@pytest.fixture(autouse=True)
def session_settings():
    """Pin the session/break-glass settings per test and restore afterwards.

    Set on the settings object rather than through the environment: the suite
    runs in one process and ``settings`` is built at first import, so an
    environment variable here would only take effect when this module happened
    to be imported first.
    """
    names = (
        "admin_session_absolute_lifetime_seconds",
        "admin_session_idle_timeout_seconds",
        "admin_session_last_seen_write_interval_seconds",
        "admin_session_max_concurrent",
        "admin_session_accept_legacy_tokens",
        "break_glass_enabled",
        "break_glass_session_lifetime_seconds",
        "break_glass_max_attempts",
        "mfa_enforcement",
    )
    saved = {name: getattr(settings, name) for name in names}
    settings.admin_session_absolute_lifetime_seconds = 28_800
    settings.admin_session_idle_timeout_seconds = 1_800
    settings.admin_session_last_seen_write_interval_seconds = 0
    settings.admin_session_max_concurrent = 10
    settings.admin_session_accept_legacy_tokens = True
    settings.break_glass_enabled = True
    settings.break_glass_session_lifetime_seconds = 3_600
    settings.break_glass_max_attempts = 5
    settings.mfa_enforcement = "off"  # MFA is exercised by its own suite
    bg.activation_limiter.reset()
    try:
        yield
    finally:
        for name, value in saved.items():
            setattr(settings, name, value)
        bg.activation_limiter.reset()


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        for email, password, platform in (
            (ADMIN_EMAIL, ADMIN_PASSWORD, True),
            (SECOND_EMAIL, ADMIN_PASSWORD, True),
        ):
            db.add(
                Operator(
                    email=email,
                    password_hash=hash_password(password),
                    role=OperatorRole.admin,
                    is_platform_admin=platform,
                )
            )
        db.add(
            Operator(
                email=VIEWER_EMAIL,
                password_hash=hash_password(VIEWER_PASSWORD),
                role=OperatorRole.readonly,
            )
        )
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        yield c
    await engine.dispose()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _login(
    c, email=ADMIN_EMAIL, password=ADMIN_PASSWORD, headers: dict | None = None
) -> str:
    response = await c.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    token = response.json()["access_token"]
    assert token
    return token


async def _operator_id(email: str) -> str:
    async with AsyncSessionLocal() as db:
        row = (
            await db.execute(select(Operator).where(Operator.email == email))
        ).scalars().one()
        return row.id


class _SessionView(SimpleNamespace):
    """Detached snapshot of a session row.

    Returned instead of the ORM object so assertions after the database session
    closes cannot trigger a lazy load, which raises MissingGreenlet under async
    SQLAlchemy rather than quietly issuing IO.
    """


async def _session_rows(operator_id: str) -> list[_SessionView]:
    async with AsyncSessionLocal() as db:
        rows = list(
            (
                await db.execute(
                    select(OperatorSession)
                    .where(OperatorSession.operator_id == operator_id)
                    .order_by(OperatorSession.created_at)
                )
            ).scalars().all()
        )
        return [
            _SessionView(
                id=row.id,
                created_at=row.created_at,
                last_seen_at=row.last_seen_at,
                absolute_expires_at=row.absolute_expires_at,
                user_agent=row.user_agent,
                is_break_glass=row.is_break_glass,
                ended_at=row.ended_at,
                end_reason=row.end_reason,
            )
            for row in rows
        ]


async def _mutate_session(session_id: str, **values) -> None:
    async with AsyncSessionLocal() as db:
        row = await db.get(OperatorSession, session_id)
        for key, value in values.items():
            setattr(row, key, value)
        await db.commit()


async def _audit(action: str) -> list[AuditEvent]:
    async with AsyncSessionLocal() as db:
        return list(
            (
                await db.execute(
                    select(AuditEvent)
                    .where(AuditEvent.action == action)
                    .order_by(AuditEvent.seq)
                )
            ).scalars().all()
        )


# =========================================================================== #
# Session creation and inventory
# =========================================================================== #
@pytest.mark.asyncio
async def test_login_opens_a_tracked_session_bound_to_the_token(client):
    token = await _login(client, headers={"User-Agent": "NodeLinkTest/1.0"})
    claims = decode_access_token(token)
    assert claims["sid"]

    rows = await _session_rows(await _operator_id(ADMIN_EMAIL))
    assert len(rows) == 1
    assert rows[0].id == claims["sid"]
    assert rows[0].ended_at is None
    assert rows[0].user_agent == "NodeLinkTest/1.0"

    listed = await client.get("/api/v1/auth/sessions", headers=_auth(token))
    assert listed.status_code == 200
    [view] = listed.json()
    assert view["is_current"] is True
    assert view["user_agent"] == "NodeLinkTest/1.0"
    # The inventory never carries anything replayable.
    assert "token" not in str(view)


@pytest.mark.asyncio
async def test_sign_in_is_audited_with_the_session_it_opened(client):
    token = await _login(client)
    [event] = await _audit("operator.session_started")
    assert event.detail["session_id"] == decode_access_token(token)["sid"]
    assert event.detail["break_glass"] is False


@pytest.mark.asyncio
async def test_one_operator_cannot_see_or_revoke_another_operators_session(client):
    victim = await _login(client, VIEWER_EMAIL, VIEWER_PASSWORD)
    victim_sid = decode_access_token(victim)["sid"]
    attacker = await _login(client)

    listed = await client.get("/api/v1/auth/sessions", headers=_auth(attacker))
    assert victim_sid not in [row["id"] for row in listed.json()]

    # Another operator's session is indistinguishable from one that never existed.
    stolen = await client.post(
        f"/api/v1/auth/sessions/{victim_sid}/revoke",
        headers=_auth(attacker),
        json={"reason": "Trying to end someone else's session"},
    )
    assert stolen.status_code == 404
    assert (
        await client.get("/api/v1/auth/me", headers=_auth(victim))
    ).status_code == 200


# =========================================================================== #
# Revocation
# =========================================================================== #
@pytest.mark.asyncio
async def test_revoking_a_session_kills_it_on_the_very_next_request(client):
    first = await _login(client)
    second = await _login(client)
    first_sid = decode_access_token(first)["sid"]

    assert (await client.get("/api/v1/auth/me", headers=_auth(first))).status_code == 200
    revoked = await client.post(
        f"/api/v1/auth/sessions/{first_sid}/revoke",
        headers=_auth(second),
        json={"reason": "Lost the laptop this session is on"},
    )
    assert revoked.status_code == 200 and revoked.json()["revoked"] == 1

    # The token is still cryptographically valid and unexpired; the session
    # behind it is not. That is the property the whole feature exists for.
    assert (await client.get("/api/v1/auth/me", headers=_auth(first))).status_code == 401
    assert (await client.get("/api/v1/auth/me", headers=_auth(second))).status_code == 200


@pytest.mark.asyncio
async def test_revoking_others_keeps_the_session_doing_the_cleanup(client):
    keep = await _login(client)
    other_a = await _login(client)
    other_b = await _login(client)

    result = await client.post(
        "/api/v1/auth/sessions/revoke-others",
        headers=_auth(keep),
        json={"reason": "Suspected credential compromise"},
    )
    assert result.status_code == 200 and result.json()["revoked"] == 2
    assert (await client.get("/api/v1/auth/me", headers=_auth(keep))).status_code == 200
    for token in (other_a, other_b):
        assert (await client.get("/api/v1/auth/me", headers=_auth(token))).status_code == 401


@pytest.mark.asyncio
async def test_revoking_an_already_dead_session_is_not_an_error(client):
    token = await _login(client)
    other = await _login(client)
    sid = decode_access_token(other)["sid"]
    body = {"reason": "Ending a stale session"}

    first = await client.post(
        f"/api/v1/auth/sessions/{sid}/revoke", headers=_auth(token), json=body
    )
    second = await client.post(
        f"/api/v1/auth/sessions/{sid}/revoke", headers=_auth(token), json=body
    )
    assert first.json()["revoked"] == 1
    # Idempotent: the dashboard's "revoke everything" must not fail on a race.
    assert second.status_code == 200 and second.json()["revoked"] == 0


@pytest.mark.asyncio
async def test_platform_admin_can_inventory_and_end_another_operators_sessions(client):
    victim = await _login(client, VIEWER_EMAIL, VIEWER_PASSWORD)
    admin = await _login(client)
    viewer_id = await _operator_id(VIEWER_EMAIL)

    listed = await client.get(
        f"/api/v1/auth/operators/{viewer_id}/sessions", headers=_auth(admin)
    )
    assert listed.status_code == 200 and len(listed.json()) == 1

    revoked = await client.post(
        f"/api/v1/auth/operators/{viewer_id}/sessions/revoke",
        headers=_auth(admin),
        json={"reason": "Offboarding"},
    )
    assert revoked.status_code == 200 and revoked.json()["revoked"] == 1
    assert (await client.get("/api/v1/auth/me", headers=_auth(victim))).status_code == 401


@pytest.mark.asyncio
async def test_session_oversight_requires_platform_admin(client):
    viewer = await _login(client, VIEWER_EMAIL, VIEWER_PASSWORD)
    admin_id = await _operator_id(ADMIN_EMAIL)
    for response in (
        await client.get(
            f"/api/v1/auth/operators/{admin_id}/sessions", headers=_auth(viewer)
        ),
        await client.post(
            f"/api/v1/auth/operators/{admin_id}/sessions/revoke",
            headers=_auth(viewer),
            json={"reason": "Not allowed"},
        ),
    ):
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_bulk_token_revocation_also_ends_tracked_sessions(client):
    token = await _login(client)
    admin_id = await _operator_id(ADMIN_EMAIL)

    revoked = await client.post("/api/v1/auth/revoke-tokens", headers=_auth(token))
    assert revoked.status_code == 204

    # The generation check refuses the token, and the session row is marked
    # terminal in the same transaction so the inventory explains itself rather
    # than showing a live session that cannot actually be used.
    assert (await client.get("/api/v1/auth/me", headers=_auth(token))).status_code == 401
    rows = await _session_rows(admin_id)
    assert rows[0].ended_at is not None
    assert rows[0].end_reason.value == "revoked_by_self"


# =========================================================================== #
# Lifetimes
# =========================================================================== #
@pytest.mark.asyncio
async def test_idle_timeout_ends_a_session_that_stops_being_used(client):
    token = await _login(client)
    sid = decode_access_token(token)["sid"]
    await _mutate_session(
        sid, last_seen_at=datetime.now(timezone.utc) - timedelta(seconds=3_600)
    )
    assert (await client.get("/api/v1/auth/me", headers=_auth(token))).status_code == 401
    rows = await _session_rows(await _operator_id(ADMIN_EMAIL))
    assert rows[0].end_reason.value == "idle_timeout"


@pytest.mark.asyncio
async def test_absolute_ceiling_ends_a_session_however_active_it_stays(client):
    token = await _login(client)
    sid = decode_access_token(token)["sid"]
    now = datetime.now(timezone.utc)
    # Continuously used (last_seen is now) but past its hard wall.
    await _mutate_session(
        sid, last_seen_at=now, absolute_expires_at=now - timedelta(seconds=1)
    )
    assert (await client.get("/api/v1/auth/me", headers=_auth(token))).status_code == 401
    rows = await _session_rows(await _operator_id(ADMIN_EMAIL))
    assert rows[0].end_reason.value == "absolute_timeout"


@pytest.mark.asyncio
async def test_activity_keeps_a_session_alive_within_the_idle_window(client):
    token = await _login(client)
    sid = decode_access_token(token)["sid"]
    # Idle-but-not-expired, then used: the request itself refreshes last_seen.
    await _mutate_session(
        sid, last_seen_at=datetime.now(timezone.utc) - timedelta(seconds=900)
    )
    assert (await client.get("/api/v1/auth/me", headers=_auth(token))).status_code == 200
    rows = await _session_rows(await _operator_id(ADMIN_EMAIL))
    assert (
        datetime.now(timezone.utc) - rows[0].last_seen_at.replace(tzinfo=timezone.utc)
    ) < timedelta(seconds=60)


@pytest.mark.asyncio
async def test_last_seen_is_not_written_on_every_request(client):
    """Idle tracking must not turn the auth path into a write per request."""
    settings.admin_session_last_seen_write_interval_seconds = 3_600
    token = await _login(client)
    sid = decode_access_token(token)["sid"]
    before = (await _session_rows(await _operator_id(ADMIN_EMAIL)))[0].last_seen_at

    for _ in range(3):
        assert (
            await client.get("/api/v1/auth/me", headers=_auth(token))
        ).status_code == 200

    after = (await _session_rows(await _operator_id(ADMIN_EMAIL)))[0].last_seen_at
    assert after == before
    assert sid


@pytest.mark.asyncio
async def test_refresh_extends_the_token_but_never_the_absolute_ceiling(client):
    token = await _login(client)
    sid = decode_access_token(token)["sid"]
    original_ceiling = (await _session_rows(await _operator_id(ADMIN_EMAIL)))[0].absolute_expires_at

    refreshed = await client.post("/api/v1/auth/session/refresh", headers=_auth(token))
    assert refreshed.status_code == 200
    new_token = refreshed.json()["access_token"]
    new_claims = decode_access_token(new_token)
    # Same session, new token.
    assert new_claims["sid"] == sid
    assert (
        await client.get("/api/v1/auth/me", headers=_auth(new_token))
    ).status_code == 200

    after = (await _session_rows(await _operator_id(ADMIN_EMAIL)))[0].absolute_expires_at
    assert after == original_ceiling


@pytest.mark.asyncio
async def test_refresh_cannot_resurrect_a_revoked_session(client):
    token = await _login(client)
    other = await _login(client)
    sid = decode_access_token(token)["sid"]
    await client.post(
        f"/api/v1/auth/sessions/{sid}/revoke",
        headers=_auth(other),
        json={"reason": "Ending it"},
    )
    assert (
        await client.post("/api/v1/auth/session/refresh", headers=_auth(token))
    ).status_code == 401


@pytest.mark.asyncio
async def test_concurrent_session_ceiling_closes_the_oldest_not_the_newest(client):
    settings.admin_session_max_concurrent = 2
    first = await _login(client)
    second = await _login(client)
    third = await _login(client)

    # Being locked out of your own account is a worse failure than a closed tab.
    assert (await client.get("/api/v1/auth/me", headers=_auth(third))).status_code == 200
    assert (await client.get("/api/v1/auth/me", headers=_auth(second))).status_code == 200
    assert (await client.get("/api/v1/auth/me", headers=_auth(first))).status_code == 401


# =========================================================================== #
# Legacy, unmanaged tokens
# =========================================================================== #
@pytest.mark.asyncio
async def test_tokens_minted_before_sessions_still_work_by_default(client):
    """Upgrading must not sign the whole fleet out mid-shift."""
    admin_id = await _operator_id(ADMIN_EMAIL)
    legacy = create_access_token(subject=admin_id, generation=0)
    assert "sid" not in decode_access_token(legacy)
    assert (await client.get("/api/v1/auth/me", headers=_auth(legacy))).status_code == 200

    # Unmanaged: it has no row, so it cannot be refreshed or inventoried.
    assert (
        await client.post("/api/v1/auth/session/refresh", headers=_auth(legacy))
    ).status_code == 409
    assert (await client.get("/api/v1/auth/sessions", headers=_auth(legacy))).json() == []


@pytest.mark.asyncio
async def test_legacy_tokens_can_be_refused_outright(client):
    settings.admin_session_accept_legacy_tokens = False
    legacy = create_access_token(
        subject=await _operator_id(ADMIN_EMAIL), generation=0
    )
    assert (await client.get("/api/v1/auth/me", headers=_auth(legacy))).status_code == 401


@pytest.mark.asyncio
async def test_a_forged_session_id_is_refused(client):
    """The `sid` is signed, but a token for one operator must not name another's."""
    victim = await _login(client, VIEWER_EMAIL, VIEWER_PASSWORD)
    victim_sid = decode_access_token(victim)["sid"]
    forged = create_access_token(
        subject=await _operator_id(ADMIN_EMAIL), generation=0, session_id=victim_sid
    )
    assert (await client.get("/api/v1/auth/me", headers=_auth(forged))).status_code == 401

    unknown = create_access_token(
        subject=await _operator_id(ADMIN_EMAIL),
        generation=0,
        session_id="00000000-0000-4000-8000-000000000000",
    )
    assert (await client.get("/api/v1/auth/me", headers=_auth(unknown))).status_code == 401


# =========================================================================== #
# Break-glass
# =========================================================================== #
async def _provision(client, token, label="Safe, London office"):
    return await client.post(
        "/api/v1/auth/break-glass",
        headers=_auth(token),
        json={"label": label, "reason": "Initial emergency provisioning"},
    )


@pytest.mark.asyncio
async def test_break_glass_credential_is_shown_once_and_stored_only_hashed(client):
    admin = await _login(client)
    created = await _provision(client, admin)
    assert created.status_code == 201
    credential = created.json()["credential"]
    assert credential.startswith("nlbg_")

    async with AsyncSessionLocal() as db:
        [account] = (await db.execute(select(BreakGlassAccount))).scalars().all()
    assert account.credential_hash.startswith("$2")
    assert credential not in account.credential_hash
    assert account.credential_fingerprint == bg.fingerprint(credential)

    # Listing never returns the credential again.
    listed = await client.get("/api/v1/auth/break-glass", headers=_auth(admin))
    assert credential not in listed.text
    assert listed.json()[0]["credential_fingerprint"] == account.credential_fingerprint


@pytest.mark.asyncio
async def test_break_glass_identity_cannot_be_reached_by_password_login(client):
    admin = await _login(client)
    await _provision(client, admin)
    async with AsyncSessionLocal() as db:
        [account] = (await db.execute(select(BreakGlassAccount))).scalars().all()
        operator = await db.get(Operator, account.operator_id)
        email = operator.email

    # The dedicated row exists but has an unusable password hash, so the
    # ordinary login path can never reach the emergency identity.
    for password in ("", "password", bg.UNUSABLE_PASSWORD_HASH):
        response = await client.post(
            "/api/v1/auth/login", json={"email": email, "password": password}
        )
        assert response.status_code in (401, 422)


@pytest.mark.asyncio
async def test_activation_opens_a_marked_short_lived_session_and_a_review(client):
    admin = await _login(client)
    credential = (await _provision(client, admin)).json()["credential"]

    activated = await client.post(
        "/api/v1/auth/break-glass/activate",
        json={"credential": credential, "reason": "All admins locked out by key loss"},
    )
    assert activated.status_code == 200
    token = activated.json()["access_token"]
    claims = decode_access_token(token)
    assert claims["amr"] == [AMR_BREAK_GLASS]
    # No step-up: it bypassed MFA, so it must not satisfy an MFA-derived gate.
    assert "sua" not in claims

    # The session works, is marked, and is bounded far more tightly than normal.
    assert (await client.get("/api/v1/auth/me", headers=_auth(token))).status_code == 200
    async with AsyncSessionLocal() as db:
        row = await db.get(OperatorSession, claims["sid"])
        assert row.is_break_glass is True
        lifetime = row.absolute_expires_at.replace(tzinfo=timezone.utc) - row.created_at.replace(
            tzinfo=timezone.utc
        )
    assert lifetime <= timedelta(seconds=settings.break_glass_session_lifetime_seconds)

    # An activation is an open incident until a human closes it.
    queue = await client.get(
        "/api/v1/auth/break-glass/activations?unreviewed_only=true",
        headers=_auth(admin),
    )
    assert len(queue.json()) == 1
    assert queue.json()[0]["session_id"] == claims["sid"]
    status_body = (
        await client.get("/api/v1/auth/break-glass/status", headers=_auth(admin))
    ).json()
    assert status_body["unreviewed_activations"] == 1


@pytest.mark.asyncio
async def test_activation_is_audited_without_recording_the_credential(client):
    admin = await _login(client)
    credential = (await _provision(client, admin)).json()["credential"]
    await client.post(
        "/api/v1/auth/break-glass/activate",
        json={"credential": credential, "reason": "Emergency access for incident 4711"},
    )

    [event] = await _audit("break_glass.activated")
    blob = str(event.detail)
    assert credential not in blob
    assert "Safe, London office" not in blob  # the label is digested
    assert event.detail["credential_fingerprint"] == bg.fingerprint(credential)
    assert "Emergency access for incident 4711" not in blob
    assert event.detail["reason_sha256"]


@pytest.mark.asyncio
async def test_a_refused_activation_is_recorded_and_rate_limited(client):
    admin = await _login(client)
    await _provision(client, admin)

    for _ in range(settings.break_glass_max_attempts):
        refused = await client.post(
            "/api/v1/auth/break-glass/activate",
            json={"credential": "nlbg_wrong-value", "reason": "Probing"},
        )
        assert refused.status_code == 401

    limited = await client.post(
        "/api/v1/auth/break-glass/activate",
        json={"credential": "nlbg_wrong-value", "reason": "Probing"},
    )
    assert limited.status_code == 429
    assert limited.headers["Retry-After"]
    # An attacker probing envelopes leaves a trail even though nothing succeeded.
    assert len(await _audit("break_glass.activation_failed")) >= 1


@pytest.mark.asyncio
async def test_rotation_invalidates_the_previous_credential(client):
    admin = await _login(client)
    created = await _provision(client, admin)
    old = created.json()["credential"]
    account_id = created.json()["account"]["id"]

    rotated = await client.post(
        f"/api/v1/auth/break-glass/{account_id}/rotate",
        headers=_auth(admin),
        json={"reason": "Envelope seal found broken"},
    )
    assert rotated.status_code == 200
    new = rotated.json()["credential"]
    assert new != old

    stale = await client.post(
        "/api/v1/auth/break-glass/activate",
        json={"credential": old, "reason": "Using the retired envelope"},
    )
    assert stale.status_code == 401
    fresh = await client.post(
        "/api/v1/auth/break-glass/activate",
        json={"credential": new, "reason": "Using the current envelope"},
    )
    assert fresh.status_code == 200


@pytest.mark.asyncio
async def test_a_disabled_account_cannot_be_activated_but_keeps_its_history(client):
    admin = await _login(client)
    created = await _provision(client, admin)
    credential = created.json()["credential"]
    account_id = created.json()["account"]["id"]

    await client.post(
        "/api/v1/auth/break-glass/activate",
        json={"credential": credential, "reason": "First use"},
    )
    disabled = await client.put(
        f"/api/v1/auth/break-glass/{account_id}/disabled",
        headers=_auth(admin),
        json={"disabled": True, "reason": "Decommissioning the London safe"},
    )
    assert disabled.status_code == 200

    refused = await client.post(
        "/api/v1/auth/break-glass/activate",
        json={"credential": credential, "reason": "After disablement"},
    )
    assert refused.status_code == 401
    # Disabling is not deletion: the activation record still resolves.
    async with AsyncSessionLocal() as db:
        assert len((await db.execute(select(BreakGlassActivation))).scalars().all()) == 1


@pytest.mark.asyncio
async def test_an_emergency_session_cannot_provision_more_emergency_access(client):
    """One stolen envelope must not become a permanent, self-renewing foothold."""
    admin = await _login(client)
    created = await _provision(client, admin)
    credential = created.json()["credential"]
    account_id = created.json()["account"]["id"]

    emergency = (
        await client.post(
            "/api/v1/auth/break-glass/activate",
            json={"credential": credential, "reason": "Locked out"},
        )
    ).json()["access_token"]

    # It is a real platform-admin session for ordinary recovery work...
    assert (
        await client.get("/api/v1/auth/me", headers=_auth(emergency))
    ).status_code == 200
    # ...but it cannot mint, rotate, or re-enable emergency credentials.
    for response in (
        await _provision(client, emergency, label="Second envelope"),
        await client.post(
            f"/api/v1/auth/break-glass/{account_id}/rotate",
            headers=_auth(emergency),
            json={"reason": "Rotating from inside the emergency"},
        ),
        await client.put(
            f"/api/v1/auth/break-glass/{account_id}/disabled",
            headers=_auth(emergency),
            json={"disabled": True, "reason": "Hiding the trail"},
        ),
    ):
        assert response.status_code == 403
        assert response.json()["detail"]["code"] == "break_glass_cannot_provision"


@pytest.mark.asyncio
async def test_review_closes_an_activation_exactly_once(client):
    admin = await _login(client)
    credential = (await _provision(client, admin)).json()["credential"]
    await client.post(
        "/api/v1/auth/break-glass/activate",
        json={"credential": credential, "reason": "Incident 4711"},
    )
    [activation] = (
        await client.get(
            "/api/v1/auth/break-glass/activations", headers=_auth(admin)
        )
    ).json()

    reviewed = await client.post(
        f"/api/v1/auth/break-glass/activations/{activation['id']}/review",
        headers=_auth(admin),
        json={"note": "Confirmed with the on-call engineer; expected"},
    )
    assert reviewed.status_code == 200
    assert reviewed.json()["reviewed_by_email"] == ADMIN_EMAIL

    # The first sign-off is the accountable one and cannot be overwritten.
    again = await client.post(
        f"/api/v1/auth/break-glass/activations/{activation['id']}/review",
        headers=_auth(admin),
        json={"note": "Trying to replace the original review"},
    )
    assert again.status_code == 409
    status_body = (
        await client.get("/api/v1/auth/break-glass/status", headers=_auth(admin))
    ).json()
    assert status_body["unreviewed_activations"] == 0


@pytest.mark.asyncio
async def test_break_glass_provisioning_requires_platform_admin(client):
    viewer = await _login(client, VIEWER_EMAIL, VIEWER_PASSWORD)
    for response in (
        await _provision(client, viewer),
        await client.get("/api/v1/auth/break-glass", headers=_auth(viewer)),
        await client.get(
            "/api/v1/auth/break-glass/activations", headers=_auth(viewer)
        ),
    ):
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_disabling_break_glass_refuses_provisioning_and_activation(client):
    admin = await _login(client)
    credential = (await _provision(client, admin)).json()["credential"]
    settings.break_glass_enabled = False

    for response in (
        await _provision(client, admin, label="Another envelope"),
        await client.post(
            "/api/v1/auth/break-glass/activate",
            json={"credential": credential, "reason": "While disabled"},
        ),
    ):
        assert response.status_code == 503
        assert response.json()["detail"]["code"] == "break_glass_disabled"


@pytest.mark.asyncio
async def test_duplicate_labels_are_refused(client):
    admin = await _login(client)
    assert (await _provision(client, admin)).status_code == 201
    assert (await _provision(client, admin)).status_code == 409


# =========================================================================== #
# Maintenance
# =========================================================================== #
@pytest.mark.asyncio
async def test_lapsed_sessions_are_marked_terminal_by_the_sweeper(client):
    token = await _login(client)
    sid = decode_access_token(token)["sid"]
    await _mutate_session(
        sid, absolute_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)
    )
    async with AsyncSessionLocal() as db:
        assert await sessions_core.expire_lapsed(db) == 1
        await db.commit()
    rows = await _session_rows(await _operator_id(ADMIN_EMAIL))
    assert rows[0].end_reason.value == "absolute_timeout"


@pytest.mark.asyncio
async def test_purging_ended_sessions_leaves_live_ones_alone(client):
    live = await _login(client)
    dead = await _login(client)
    dead_sid = decode_access_token(dead)["sid"]
    await client.post(
        f"/api/v1/auth/sessions/{dead_sid}/revoke",
        headers=_auth(live),
        json={"reason": "Ending it"},
    )
    await _mutate_session(
        dead_sid, ended_at=datetime.now(timezone.utc) - timedelta(days=120)
    )

    async with AsyncSessionLocal() as db:
        assert await sessions_core.purge_ended(db, older_than_days=90) == 1
        await db.commit()
    remaining = await _session_rows(await _operator_id(ADMIN_EMAIL))
    assert [row.id for row in remaining] == [decode_access_token(live)["sid"]]
