# SPDX-License-Identifier: AGPL-3.0-only
"""Refusal branches of operator administration, MFA, and session oversight (#284).

The happy paths of these routers are covered by their own suites; this file
drives the 404/409/401/503 branches those suites never reach: an unknown
operator, client, membership, credential, break-glass account or activation; a
change that would leave state as it already is; a token of the wrong kind at
enrolment; and the completion-time re-checks of the WebAuthn registration
ceremony. Every case asserts the status code and the refusal detail/code.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

os.environ.setdefault(
    "DATABASE_URL", "sqlite+aiosqlite:///./test_operator_admin_refusals.db"
)
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from jose import jwt  # noqa: E402
from sqlalchemy import event  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.api import deps  # noqa: E402
from app.core import break_glass as bg  # noqa: E402
from app.core import mfa  # noqa: E402
from app.core import webauthn as wa  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import (  # noqa: E402
    AMR_PASSWORD,
    create_mfa_pending_token,
    hash_password,
)
from app.main import app  # noqa: E402
from app.models.models import Operator, OperatorRole  # noqa: E402
from tests.webauthn_authenticator import SoftwareAuthenticator  # noqa: E402

RP_ID = "rmm.test"
ORIGIN = "https://rmm.test"

PASSWORD = "correct-horse-battery"
ADMIN_ID = "op-admin"
ADMIN_EMAIL = "admin@nodelink.test"
SECOND_ADMIN_ID = "op-second-admin"
OPERATOR_ID = "op-operator"
OPERATOR_EMAIL = "operator@nodelink.test"
MISSING = "does-not-exist"
REASON = "refusal coverage"


@pytest.fixture(autouse=True)
def pinned_settings():
    """Pin MFA and break-glass settings on the settings object, then restore.

    Set on the object rather than through the environment: the suite runs in
    one process and ``settings`` is built at first import, so an environment
    variable set here would only apply when this module happened to load first.
    """
    names = (
        "public_base_url",
        "mfa_rp_id",
        "mfa_allowed_origins",
        "mfa_enforcement",
        "mfa_required_minimum_role",
        "mfa_require_user_verification",
        "mfa_max_credentials_per_operator",
        "mfa_step_up_max_age_seconds",
        "break_glass_enabled",
    )
    saved = {name: getattr(settings, name) for name in names}
    settings.public_base_url = ORIGIN
    settings.mfa_rp_id = None
    settings.mfa_allowed_origins = ""
    settings.mfa_enforcement = "optional"
    settings.mfa_required_minimum_role = "admin"
    settings.mfa_require_user_verification = True
    settings.mfa_max_credentials_per_operator = 10
    settings.mfa_step_up_max_age_seconds = 900
    settings.break_glass_enabled = True
    mfa.mfa_limiter.reset()
    try:
        yield
    finally:
        for name, value in saved.items():
            setattr(settings, name, value)
        mfa.mfa_limiter.reset()


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add_all(
            [
                Operator(
                    id=ADMIN_ID,
                    email=ADMIN_EMAIL,
                    password_hash=hash_password(PASSWORD),
                    role=OperatorRole.admin,
                    is_platform_admin=True,
                ),
                # A second active platform admin, so the last-admin guards never
                # mask the refusal a test is actually about.
                Operator(
                    id=SECOND_ADMIN_ID,
                    email="second-admin@nodelink.test",
                    password_hash=hash_password(PASSWORD),
                    role=OperatorRole.admin,
                    is_platform_admin=True,
                ),
                Operator(
                    id=OPERATOR_ID,
                    email=OPERATOR_EMAIL,
                    password_hash=hash_password(PASSWORD),
                    role=OperatorRole.operator,
                ),
            ]
        )
        await db.flush()
        account, _credential = await bg.create_account(
            db, label="Sealed envelope", created_by_email=ADMIN_EMAIL
        )
        account_id = account.id
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://t/api/v1"
    ) as c:
        c.break_glass_account_id = account_id
        yield c
    await engine.dispose()


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _login(c, email: str = ADMIN_EMAIL) -> dict:
    response = await c.post(
        "/auth/login", json={"email": email, "password": PASSWORD}
    )
    assert response.status_code == 200, response.text
    return response.json()


async def _session(c, email: str = ADMIN_EMAIL) -> str:
    """A full session from a password alone (the operator is not enrolled)."""
    token = (await _login(c, email))["access_token"]
    assert token
    return token


def _authenticator(**kwargs) -> SoftwareAuthenticator:
    kwargs.setdefault("rp_id", RP_ID)
    kwargs.setdefault("origin", ORIGIN)
    return SoftwareAuthenticator(**kwargs)


async def _registration_options(c, token: str) -> bytes:
    options = await c.post("/auth/mfa/credentials/options", headers=_auth(token))
    assert options.status_code == 200, options.text
    return wa.b64url_decode(options.json()["challenge"])


async def _complete_registration(c, token: str, created: dict, name="Test key"):
    return await c.post(
        "/auth/mfa/credentials",
        headers=_auth(token),
        json={
            "name": name,
            "client_data_json": created["client_data_json"],
            "attestation_object": created["attestation_object"],
            "transports": ["usb"],
        },
    )


async def _enrolled_step_up_session(c) -> tuple[str, dict]:
    """Enrol the admin, log in with the key, return (fresh session, credential)."""
    authenticator = _authenticator()
    bootstrap = await _session(c)
    challenge = await _registration_options(c, bootstrap)
    registered = await _complete_registration(
        c, bootstrap, authenticator.register(challenge)
    )
    assert registered.status_code == 201, registered.text

    pending = (await _login(c))["mfa_token"]
    options = await c.post("/auth/mfa/login/options", headers=_auth(pending))
    assert options.status_code == 200, options.text
    signed = authenticator.assert_(wa.b64url_decode(options.json()["challenge"]))
    verified = await c.post(
        "/auth/mfa/login/verify",
        headers=_auth(pending),
        json={
            "credential_id": signed["id"],
            "client_data_json": signed["client_data_json"],
            "authenticator_data": signed["authenticator_data"],
            "signature": signed["signature"],
        },
    )
    assert verified.status_code == 200, verified.text
    return verified.json()["access_token"], registered.json()


def _detail_matches(response: httpx.Response, expected) -> None:
    detail = response.json()["detail"]
    if isinstance(expected, str):
        assert detail == expected, detail
    else:
        assert detail["code"] == expected["code"], detail


# --------------------------------------------------------------------------- #
# Unknown targets and no-op changes, driven by an unenrolled platform admin
# (step-up is vacuous for an admin with no authenticator).
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("method", "path", "body", "status", "expected"),
    [
        # app/api/auth.py
        (
            "PUT",
            f"/auth/operators/{MISSING}/role",
            {"role": "readonly", "reason": REASON},
            404,
            "Operator not found",
        ),
        (
            "PUT",
            f"/auth/operators/{OPERATOR_ID}/role",
            {"role": "operator", "reason": REASON},
            409,
            {"code": "operator_role_unchanged"},
        ),
        (
            "PUT",
            f"/auth/operators/{MISSING}/script-permission",
            {"scope": "global", "reason": REASON},
            404,
            "Operator not found",
        ),
        (
            "PUT",
            f"/auth/operators/{OPERATOR_ID}/script-permission",
            {"scope": "site", "scope_id": MISSING, "reason": REASON},
            404,
            "Site not found",
        ),
        (
            "PUT",
            f"/auth/operators/{OPERATOR_ID}/script-permission",
            {"scope": "agent", "scope_id": MISSING, "reason": REASON},
            404,
            "Agent not found",
        ),
        (
            "POST",
            f"/auth/operators/{MISSING}/script-permission/revoke",
            {"reason": REASON},
            404,
            "Operator not found",
        ),
        (
            "POST",
            f"/auth/operators/{OPERATOR_ID}/script-permission/revoke",
            {"reason": REASON},
            409,
            {"code": "script_permission_not_granted"},
        ),
        (
            "POST",
            f"/auth/operators/{MISSING}/revoke-tokens",
            None,
            404,
            "Operator not found",
        ),
        (
            "POST",
            f"/auth/operators/{OPERATOR_ID}/client-memberships",
            {"client_id": MISSING, "role": "client_readonly", "reason": REASON},
            404,
            "Client not found",
        ),
        (
            "POST",
            f"/auth/operators/{OPERATOR_ID}/client-memberships/{MISSING}/revoke",
            {"reason": REASON},
            404,
            "Client membership not found",
        ),
        (
            "PUT",
            f"/auth/operators/{OPERATOR_ID}/platform-admin",
            {"is_platform_admin": False, "reason": REASON},
            409,
            {"code": "platform_admin_unchanged"},
        ),
        # app/api/admin_sessions.py
        ("GET", f"/auth/operators/{MISSING}/sessions", None, 404, "Operator not found"),
        (
            "POST",
            f"/auth/operators/{MISSING}/sessions/revoke",
            {"reason": REASON},
            404,
            "Operator not found",
        ),
        (
            "PUT",
            f"/auth/break-glass/{MISSING}/disabled",
            {"disabled": True, "reason": REASON},
            404,
            "Break-glass account not found",
        ),
        (
            "PUT",
            "/auth/break-glass/{account}/disabled",
            {"disabled": False, "reason": REASON},
            409,
            {"code": "break_glass_state_unchanged"},
        ),
        (
            "POST",
            f"/auth/break-glass/activations/{MISSING}/review",
            {"note": REASON},
            404,
            "Activation not found",
        ),
        # app/api/mfa.py
        (
            "POST",
            f"/auth/operators/{MISSING}/mfa/reset",
            {"reason": REASON},
            404,
            "Operator not found",
        ),
        (
            "POST",
            "/auth/mfa/email",
            {"reason": REASON},
            404,
            "No email factor registered",
        ),
        (
            "POST",
            "/auth/mfa/step-up/options",
            None,
            409,
            {"code": "enrollment_required"},
        ),
    ],
)
async def test_admin_refusals(client, method, path, body, status, expected):
    token = await _session(client)
    response = await client.request(
        method,
        path.format(account=client.break_glass_account_id),
        headers=_auth(token),
        json=body,
    )
    assert response.status_code == status, response.text
    _detail_matches(response, expected)


async def test_create_operator_loses_an_email_race_with_409(client):
    """The pre-check passes, then a concurrent insert of the same email wins.

    Simulated by flushing a competing row for the same address alongside the
    new operator, which is what a transaction committed between the check and
    the insert looks like to the unique constraint.
    """
    token = await _session(client)
    email = "racer@nodelink.test"

    def add_competitor(session, _flush_context, _instances):
        if any(
            isinstance(obj, Operator) and obj.email == email for obj in session.new
        ) and not session.info.get("raced"):
            session.info["raced"] = True
            session.add(
                Operator(
                    email=email,
                    password_hash=hash_password(PASSWORD),
                    role=OperatorRole.readonly,
                )
            )

    event.listen(Session, "before_flush", add_competitor)
    try:
        response = await client.post(
            "/auth/operators",
            headers=_auth(token),
            json={
                "email": email,
                "password": "a-long-enough-password-123",
                "role": "readonly",
            },
        )
    finally:
        event.remove(Session, "before_flush", add_competitor)
    assert response.status_code == 409, response.text
    assert response.json()["detail"] == "Email already registered"


# --------------------------------------------------------------------------- #
# MFA availability and enrolment tokens
# --------------------------------------------------------------------------- #
async def test_ceremonies_fail_closed_without_a_resolvable_relying_party(client):
    """No RP ID and no public base URL: refuse rather than guess the scope."""
    token = await _session(client)
    settings.public_base_url = ""
    settings.mfa_rp_id = None
    response = await client.post("/auth/mfa/step-up/options", headers=_auth(token))
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "mfa_not_configured"


def _foreign_type_token() -> str:
    """A correctly signed token whose type no enrolment surface accepts."""
    return jwt.encode(
        {
            "sub": ADMIN_ID,
            "gen": 0,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
            "typ": "break_glass_activation",
            "amr": [AMR_PASSWORD],
        },
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )


@pytest.mark.parametrize(
    "make_token",
    [
        pytest.param(_foreign_type_token, id="unknown-token-type"),
        # Enrolment is optional here, so the restricted post-password token is
        # not an enrolment credential: it must finish a login instead.
        pytest.param(
            lambda: create_mfa_pending_token(ADMIN_ID), id="pending-token-not-required"
        ),
    ],
)
async def test_enrolment_refuses_tokens_that_are_not_enrolment_credentials(
    client, make_token
):
    response = await client.post(
        "/auth/mfa/credentials/options", headers=_auth(make_token())
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired token"


# --------------------------------------------------------------------------- #
# Registration completion
# --------------------------------------------------------------------------- #
async def test_registration_without_an_outstanding_challenge_is_refused(client):
    token = await _session(client)
    created = _authenticator().register(wa.generate_challenge())
    response = await _complete_registration(client, token, created)
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "challenge_expired"


async def test_registration_with_a_failing_attestation_is_refused(client):
    token = await _session(client)
    challenge = await _registration_options(client, token)
    created = _authenticator(origin="https://rmm.test.evil.example").register(
        challenge
    )
    response = await _complete_registration(client, token, created)
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "origin_mismatch"


async def test_registration_rechecks_the_credential_ceiling_at_completion(client):
    """Options and completion are separate requests; the ceiling is re-checked."""
    token = await _session(client)
    challenge = await _registration_options(client, token)
    # Stands in for a parallel ceremony that completed after these options were
    # issued and filled the operator's last slot.
    settings.mfa_max_credentials_per_operator = 0
    response = await _complete_registration(
        client, token, _authenticator().register(challenge)
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "credential_limit_reached"


# --------------------------------------------------------------------------- #
# Credential management (requires a step-up-fresh enrolled session)
# --------------------------------------------------------------------------- #
async def test_renaming_an_unknown_credential_is_404(client):
    session, _credential = await _enrolled_step_up_session(client)
    response = await client.put(
        f"/auth/mfa/credentials/{MISSING}",
        headers=_auth(session),
        json={"name": "Renamed"},
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "Credential not found"


async def test_renaming_a_credential_to_its_current_name_is_409(client):
    session, credential = await _enrolled_step_up_session(client)
    response = await client.put(
        f"/auth/mfa/credentials/{credential['id']}",
        headers=_auth(session),
        json={"name": credential["name"]},
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "credential_name_unchanged"


async def test_require_mfa_verified_refuses_a_password_only_enrolled_session(client):
    """`require_mfa_verified` is not mounted on any route, so it is driven directly."""
    await _enrolled_step_up_session(client)
    async with AsyncSessionLocal() as db:
        operator = await db.get(Operator, ADMIN_ID)
        operator.session_amr = frozenset({AMR_PASSWORD})
        with pytest.raises(HTTPException) as refused:
            await deps.require_mfa_verified(operator=operator, db=db)
    assert refused.value.status_code == 403
    assert refused.value.detail["code"] == "mfa_verification_required"
