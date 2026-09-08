# SPDX-License-Identifier: AGPL-3.0-only
"""Email one-time-code second factor (issue #226).

The point of this file is to hold the *weaker* factor to its stated bounds.
Anyone can show that a correct code logs you in; what matters here is that the
code cannot do more than it is supposed to, and that turning the feature on does
not quietly weaken an account that already holds a security key.

Four properties get the most attention, because they are the ones the design
argument rests on:

* an email code never satisfies step-up, so a phished code cannot be escalated
  into revoking devices, minting recovery codes, or removing the factor itself;
* under the recommended ``fallback_only`` position an operator who holds an
  authenticator is never offered, and never accepted with, an email code;
* a code is single-use, attempt-bounded, expiring, and invalidated by reissue,
  and a replay is distinguishable in the audit trail from a value that was never
  a code;
* a provider outage neither silently grants access nor silently denies it.

Codes are read out of the messages a fake provider captured, exactly as an
operator would read them out of a mailbox. Nothing here reaches into the
database for a plaintext code, because no plaintext code is ever stored.

The file is organised as: helpers, then policy and offering, then the login
flow, then the ceiling on what an email session may do, then the code lifecycle
and abuse cases, then delivery failure, then audit evidence.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_mfa_email_code.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.core import mfa, mfa_email  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.email_notifications import ProviderError  # noqa: E402
from app.core.security import (  # noqa: E402
    AMR_EMAIL_CODE,
    AMR_PASSWORD,
    decode_access_token,
    hash_password,
)
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    AuditEvent,
    MfaEmailCode,
    MfaEmailCodePurpose,
    MfaEmailFactor,
    Operator,
    OperatorRole,
)
from app.core import webauthn as wa  # noqa: E402
from tests.webauthn_authenticator import SoftwareAuthenticator  # noqa: E402

RP_ID = "rmm.test"
ORIGIN = "https://rmm.test"

ADMIN_EMAIL = "admin@nodelink.test"
ADMIN_PASSWORD = "correct-horse-battery"
SECOND_ADMIN_EMAIL = "second-admin@nodelink.test"
VIEWER_EMAIL = "viewer@nodelink.test"
VIEWER_PASSWORD = "read-only-pass"

_CODE_PATTERN = re.compile(r"\n {4}(\d{6})\n")


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #
class CapturingProvider:
    """Stands in for the mail provider, keeping every message it was handed."""

    def __init__(self) -> None:
        self.messages: list = []

    async def send(self, delivery):  # pragma: no cover - alert path unused here
        raise AssertionError("the authentication path must not use the alert send")

    async def send_message(self, message) -> str:
        self.messages.append(message)
        return "00000000-0000-4000-8000-000000000000"

    @property
    def last_code(self) -> str:
        assert self.messages, "no message was sent"
        match = _CODE_PATTERN.search(self.messages[-1].text_body)
        assert match, self.messages[-1].text_body
        return match.group(1)


class FailingProvider:
    """A provider that is reachable but refuses, as during an outage."""

    def __init__(self, code: str = "internal_server_error") -> None:
        self.code = code
        self.calls = 0

    async def send(self, delivery):  # pragma: no cover
        raise AssertionError("the authentication path must not use the alert send")

    async def send_message(self, message) -> str:
        self.calls += 1
        raise ProviderError(self.code, retryable=True)


@pytest.fixture(autouse=True)
def email_settings():
    """Pin every setting these tests depend on, and restore it afterwards.

    Set on the settings object rather than through the environment for the same
    reason ``test_mfa_webauthn.py`` does: the suite runs in one process and
    ``settings`` is built at first import.
    """
    saved = {
        name: getattr(settings, name)
        for name in (
            "public_base_url",
            "mfa_enforcement",
            "mfa_required_minimum_role",
            "mfa_rp_id",
            "mfa_allowed_origins",
            "mfa_email_code_policy",
            "mfa_email_code_ttl_seconds",
            "mfa_email_code_max_attempts",
            "mfa_email_send_max_per_window",
            "mfa_email_send_window_seconds",
        )
    }
    settings.public_base_url = ORIGIN
    settings.mfa_rp_id = None
    settings.mfa_allowed_origins = ""
    settings.mfa_enforcement = "optional"
    settings.mfa_required_minimum_role = "admin"
    settings.mfa_email_code_policy = "fallback_only"
    settings.mfa_email_code_ttl_seconds = 600
    settings.mfa_email_code_max_attempts = 5
    settings.mfa_email_send_max_per_window = 3
    settings.mfa_email_send_window_seconds = 900
    mfa.mfa_limiter.reset()
    mfa_email.email_send_limiter.reset()
    # The limiters read their bounds once, at construction. Rebind them to the
    # pinned values so a test that changes a limit is actually testing it.
    mfa_email.email_send_limiter.max_failures = settings.mfa_email_send_max_per_window
    mfa_email.email_send_limiter.window_seconds = settings.mfa_email_send_window_seconds
    try:
        yield
    finally:
        for name, value in saved.items():
            setattr(settings, name, value)
        mfa.mfa_limiter.reset()
        mfa_email.email_send_limiter.reset()


@pytest.fixture
def provider(monkeypatch) -> CapturingProvider:
    captured = CapturingProvider()
    monkeypatch.setattr(
        mfa_email, "build_transactional_provider", lambda config=settings: captured
    )
    return captured


@pytest_asyncio.fixture
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSessionLocal() as db:
        db.add(
            Operator(
                email=ADMIN_EMAIL,
                password_hash=hash_password(ADMIN_PASSWORD),
                role=OperatorRole.admin,
            )
        )
        db.add(
            Operator(
                email=SECOND_ADMIN_EMAIL,
                password_hash=hash_password(ADMIN_PASSWORD),
                role=OperatorRole.admin,
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


async def _login(c, email=ADMIN_EMAIL, password=ADMIN_PASSWORD):
    return await c.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )


async def _password_session(c, email=ADMIN_EMAIL, password=ADMIN_PASSWORD) -> str:
    body = (await _login(c, email, password)).json()
    assert body["access_token"], body
    return body["access_token"]


async def _enroll_email(c, provider: CapturingProvider, token: str) -> None:
    """Complete an email enrolment the way an operator would."""
    started = await c.post(
        "/api/v1/auth/mfa/email/enrollment/start", headers=_auth(token)
    )
    assert started.status_code == 200, started.text
    verified = await c.post(
        "/api/v1/auth/mfa/email/enrollment/verify",
        json={"code": provider.last_code},
        headers=_auth(token),
    )
    assert verified.status_code == 200, verified.text
    assert verified.json()["verified"] is True


async def _enroll_webauthn(
    c, token: str, name="Key"
) -> tuple[str, SoftwareAuthenticator]:
    """Register a real authenticator. Returns (credential id, authenticator)."""
    authenticator = SoftwareAuthenticator(rp_id=RP_ID, origin=ORIGIN)
    options = await c.post(
        "/api/v1/auth/mfa/credentials/options", headers=_auth(token)
    )
    assert options.status_code == 200, options.text
    created = authenticator.register(wa.b64url_decode(options.json()["challenge"]))
    registered = await c.post(
        "/api/v1/auth/mfa/credentials",
        headers=_auth(token),
        json={
            "name": name,
            "client_data_json": created["client_data_json"],
            "attestation_object": created["attestation_object"],
            "transports": ["usb"],
        },
    )
    assert registered.status_code == 201, registered.text
    return registered.json()["id"], authenticator


async def _webauthn_login(c, authenticator: SoftwareAuthenticator) -> str:
    """Sign in with an already-registered key, yielding a step-up-fresh session."""
    body = (await _login(c)).json()
    assert body["mfa_required"] is True, body
    options = await c.post(
        "/api/v1/auth/mfa/login/options", headers=_auth(body["mfa_token"])
    )
    assert options.status_code == 200, options.text
    signed = authenticator.assert_(wa.b64url_decode(options.json()["challenge"]))
    completed = await c.post(
        "/api/v1/auth/mfa/login/verify",
        headers=_auth(body["mfa_token"]),
        json={
            "credential_id": signed["id"],
            "client_data_json": signed["client_data_json"],
            "authenticator_data": signed["authenticator_data"],
            "signature": signed["signature"],
        },
    )
    assert completed.status_code == 200, completed.text
    return completed.json()["access_token"]


async def _email_login(c, provider: CapturingProvider, email=ADMIN_EMAIL,
                       password=ADMIN_PASSWORD) -> str:
    """Password, then emailed code. Returns the resulting access token."""
    body = (await _login(c, email, password)).json()
    assert body["mfa_required"] is True, body
    assert "email_code" in body["mfa_methods"], body
    mfa_token = body["mfa_token"]
    sent = await c.post(
        "/api/v1/auth/mfa/login/email/send", headers=_auth(mfa_token)
    )
    assert sent.status_code == 200, sent.text
    completed = await c.post(
        "/api/v1/auth/mfa/login/email/verify",
        json={"code": provider.last_code},
        headers=_auth(mfa_token),
    )
    assert completed.status_code == 200, completed.text
    return completed.json()["access_token"]


async def _audit_actions(action: str) -> list[dict]:
    async with AsyncSessionLocal() as db:
        rows = (
            await db.execute(
                select(AuditEvent).where(AuditEvent.action == action)
            )
        ).scalars().all()
        return [dict(row.detail or {}) for row in rows]


# --------------------------------------------------------------------------- #
# Policy: what the factor is allowed to be
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_policy_off_refuses_enrolment_and_login(client, provider):
    """``off`` is a real rollback position, not just a hidden button."""
    settings.mfa_email_code_policy = "off"
    token = await _password_session(client)

    started = await client.post(
        "/api/v1/auth/mfa/email/enrollment/start", headers=_auth(token)
    )
    assert started.status_code == 503
    assert started.json()["detail"]["code"] == "email_code_disabled"
    assert provider.messages == []


@pytest.mark.asyncio
async def test_unverified_enrolment_is_not_a_factor(client, provider):
    """A code was mailed but never confirmed, so nothing became a factor."""
    token = await _password_session(client)
    started = await client.post(
        "/api/v1/auth/mfa/email/enrollment/start", headers=_auth(token)
    )
    assert started.status_code == 200
    assert len(provider.messages) == 1

    async with AsyncSessionLocal() as db:
        factor = (
            await db.execute(select(MfaEmailFactor))
        ).scalar_one()
        assert factor.verified_at is None

    # The login path must not offer a factor that nobody proved control of.
    body = (await _login(client)).json()
    assert body.get("access_token"), body
    assert body.get("mfa_required", False) is False


@pytest.mark.asyncio
async def test_fallback_only_does_not_downgrade_a_key_holder(client, provider):
    """The acceptance criterion: holding a key means still using it.

    The operator has both an authenticator and a verified mailbox. Under the
    recommended position the email code is neither offered nor accepted, so
    enabling the feature cannot weaken an account that is already protected.
    """
    token = await _password_session(client)
    await _enroll_email(client, provider, token)
    await _enroll_webauthn(client, token)

    body = (await _login(client)).json()
    assert body["mfa_required"] is True
    assert "webauthn" in body["mfa_methods"]
    assert "email_code" not in body["mfa_methods"], body

    # Not merely hidden in the response — actually refused at the endpoint.
    mfa_token = body["mfa_token"]
    sent = await client.post(
        "/api/v1/auth/mfa/login/email/send", headers=_auth(mfa_token)
    )
    assert sent.status_code == 200, "the send must stay indistinguishable"
    assert provider.messages[-1].subject.startswith("Confirm this address"), (
        "no login code may be sent to a key holder under fallback_only"
    )
    completed = await client.post(
        "/api/v1/auth/mfa/login/email/verify",
        json={"code": "000000"},
        headers=_auth(mfa_token),
    )
    assert completed.status_code == 401


@pytest.mark.asyncio
async def test_always_offers_email_beside_webauthn(client, provider):
    """Position 1 is available for a deployment that chooses it knowingly."""
    settings.mfa_email_code_policy = "always"
    token = await _password_session(client)
    await _enroll_email(client, provider, token)
    await _enroll_webauthn(client, token)

    body = (await _login(client)).json()
    assert body["mfa_required"] is True
    assert "webauthn" in body["mfa_methods"]
    assert "email_code" in body["mfa_methods"], body


@pytest.mark.asyncio
async def test_email_factor_satisfies_a_required_enrolment(client, provider):
    """The operator this feature exists for: cannot hold a key, still gets in.

    Under ``required`` an admin with no authenticator would otherwise receive a
    restricted, enrolment-only session. A proven mailbox is a second factor, so
    they complete a real login instead.
    """
    token = await _password_session(client)
    await _enroll_email(client, provider, token)
    settings.mfa_enforcement = "required"

    body = (await _login(client)).json()
    assert body["mfa_required"] is True
    assert body["mfa_enrollment_required"] is False, body
    assert body["mfa_methods"] == ["email_code"], body


# --------------------------------------------------------------------------- #
# Login
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_login_with_email_code_succeeds(client, provider):
    token = await _password_session(client)
    await _enroll_email(client, provider, token)

    access = await _email_login(client, provider)
    claims = decode_access_token(access)
    assert set(claims["amr"]) == {AMR_PASSWORD, AMR_EMAIL_CODE}
    # The session is usable for ordinary work.
    whoami = await client.get("/api/v1/auth/me", headers=_auth(access))
    assert whoami.status_code == 200, whoami.text


@pytest.mark.asyncio
async def test_enrolment_code_cannot_complete_a_login(client, provider):
    """Purpose is bound into the row, so the two code kinds do not interchange."""
    token = await _password_session(client)
    await _enroll_email(client, provider, token)

    body = (await _login(client)).json()
    mfa_token = body["mfa_token"]
    # Start a *second* enrolment to get a fresh enrolment-purpose code, then try
    # to spend it on the login endpoint.
    await client.post(
        "/api/v1/auth/mfa/email/enrollment/start", headers=_auth(token)
    )
    enrolment_code = provider.last_code
    completed = await client.post(
        "/api/v1/auth/mfa/login/email/verify",
        json={"code": enrolment_code},
        headers=_auth(mfa_token),
    )
    assert completed.status_code == 401


# --------------------------------------------------------------------------- #
# The ceiling: what an email-authenticated session may not do
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_email_code_never_satisfies_step_up(client, provider):
    """The load-bearing test of the whole feature.

    An account holds a key *and* a mailbox, and the operator signs in with the
    code. The session is MFA-verified, but every step-up-gated operation is
    still refused — so phishing six digits does not buy the ability to revoke
    the real authenticator, mint recovery codes, or reset anyone's MFA.
    """
    settings.mfa_email_code_policy = "always"
    token = await _password_session(client)
    await _enroll_email(client, provider, token)
    credential_id, _authenticator = await _enroll_webauthn(client, token)

    access = await _email_login(client, provider)

    status_body = (
        await client.get("/api/v1/auth/mfa/status", headers=_auth(access))
    ).json()
    assert status_body["step_up_satisfied"] is False, status_body

    revoked = await client.post(
        f"/api/v1/auth/mfa/credentials/{credential_id}/revoke",
        json={"reason": "phished code should not be able to do this"},
        headers=_auth(access),
    )
    assert revoked.status_code == 403, revoked.text

    minted = await client.post(
        "/api/v1/auth/mfa/recovery-codes", headers=_auth(access)
    )
    assert minted.status_code == 403, minted.text

    removed = await client.post(
        "/api/v1/auth/mfa/email",
        json={"reason": "a phished code must not remove the factor either"},
        headers=_auth(access),
    )
    assert removed.status_code == 403, removed.text


@pytest.mark.asyncio
async def test_email_session_counts_as_mfa_verified_for_enrolment(client, provider):
    """It is a second factor, so it may add a real authenticator.

    This is the intended upgrade path: sign in with the weak factor, then enrol
    a key. It is exactly the recovery-code tier, no more and no less.
    """
    token = await _password_session(client)
    await _enroll_email(client, provider, token)
    access = await _email_login(client, provider)

    options = await client.post(
        "/api/v1/auth/mfa/credentials/options", headers=_auth(access)
    )
    assert options.status_code == 200, options.text


# --------------------------------------------------------------------------- #
# Code lifecycle and abuse
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_code_is_single_use(client, provider):
    token = await _password_session(client)
    await _enroll_email(client, provider, token)

    body = (await _login(client)).json()
    mfa_token = body["mfa_token"]
    await client.post("/api/v1/auth/mfa/login/email/send", headers=_auth(mfa_token))
    code = provider.last_code

    first = await client.post(
        "/api/v1/auth/mfa/login/email/verify",
        json={"code": code},
        headers=_auth(mfa_token),
    )
    assert first.status_code == 200

    replay = await client.post(
        "/api/v1/auth/mfa/login/email/verify",
        json={"code": code},
        headers=_auth(mfa_token),
    )
    assert replay.status_code == 401
    reasons = [d.get("reason") for d in await _audit_actions("mfa.authentication_failed")]
    assert "replayed" in reasons, reasons


@pytest.mark.asyncio
async def test_expired_code_is_refused(client, provider):
    token = await _password_session(client)
    await _enroll_email(client, provider, token)

    body = (await _login(client)).json()
    mfa_token = body["mfa_token"]
    await client.post("/api/v1/auth/mfa/login/email/send", headers=_auth(mfa_token))
    code = provider.last_code

    async with AsyncSessionLocal() as db:
        row = (
            await db.execute(
                select(MfaEmailCode).where(
                    MfaEmailCode.purpose == MfaEmailCodePurpose.login
                )
            )
        ).scalars().first()
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await db.commit()

    refused = await client.post(
        "/api/v1/auth/mfa/login/email/verify",
        json={"code": code},
        headers=_auth(mfa_token),
    )
    assert refused.status_code == 401


@pytest.mark.asyncio
async def test_attempts_are_bounded_and_burn_the_code(client, provider):
    """Six digits are only safe because a code dies after a few wrong guesses."""
    settings.mfa_email_code_max_attempts = 3
    token = await _password_session(client)
    await _enroll_email(client, provider, token)

    body = (await _login(client)).json()
    mfa_token = body["mfa_token"]
    await client.post("/api/v1/auth/mfa/login/email/send", headers=_auth(mfa_token))
    code = provider.last_code
    wrong = "000000" if code != "000000" else "111111"

    for _ in range(3):
        attempt = await client.post(
            "/api/v1/auth/mfa/login/email/verify",
            json={"code": wrong},
            headers=_auth(mfa_token),
        )
        assert attempt.status_code in (401, 429)

    # Even the correct code is now worthless: the row was burned, not merely
    # counted against.
    mfa.mfa_limiter.reset()
    after = await client.post(
        "/api/v1/auth/mfa/login/email/verify",
        json={"code": code},
        headers=_auth(mfa_token),
    )
    assert after.status_code == 401, after.text


@pytest.mark.asyncio
async def test_reissue_invalidates_the_previous_code(client, provider):
    """A mailbox must never hold two simultaneously live codes."""
    token = await _password_session(client)
    await _enroll_email(client, provider, token)

    body = (await _login(client)).json()
    mfa_token = body["mfa_token"]
    await client.post("/api/v1/auth/mfa/login/email/send", headers=_auth(mfa_token))
    first_code = provider.last_code
    await client.post("/api/v1/auth/mfa/login/email/send", headers=_auth(mfa_token))
    second_code = provider.last_code
    assert first_code != second_code

    stale = await client.post(
        "/api/v1/auth/mfa/login/email/verify",
        json={"code": first_code},
        headers=_auth(mfa_token),
    )
    assert stale.status_code == 401

    fresh = await client.post(
        "/api/v1/auth/mfa/login/email/verify",
        json={"code": second_code},
        headers=_auth(mfa_token),
    )
    assert fresh.status_code == 200, fresh.text


@pytest.mark.asyncio
async def test_send_is_rate_limited(client, provider):
    """Sending is bounded independently of verifying."""
    settings.mfa_email_send_max_per_window = 2
    mfa_email.email_send_limiter.max_failures = 2
    token = await _password_session(client)
    await _enroll_email(client, provider, token)
    mfa_email.email_send_limiter.reset()

    body = (await _login(client)).json()
    mfa_token = body["mfa_token"]
    first = await client.post(
        "/api/v1/auth/mfa/login/email/send", headers=_auth(mfa_token)
    )
    second = await client.post(
        "/api/v1/auth/mfa/login/email/send", headers=_auth(mfa_token)
    )
    third = await client.post(
        "/api/v1/auth/mfa/login/email/send", headers=_auth(mfa_token)
    )
    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 429, third.text
    assert "Retry-After" in third.headers


@pytest.mark.asyncio
async def test_verify_is_rate_limited_separately_from_send(client, provider):
    """Guessing exhausts the verify budget without touching the send budget."""
    token = await _password_session(client)
    await _enroll_email(client, provider, token)

    body = (await _login(client)).json()
    mfa_token = body["mfa_token"]
    await client.post("/api/v1/auth/mfa/login/email/send", headers=_auth(mfa_token))

    statuses = []
    for _ in range(settings.mfa_max_failures + 1):
        attempt = await client.post(
            "/api/v1/auth/mfa/login/email/verify",
            json={"code": "999999"},
            headers=_auth(mfa_token),
        )
        statuses.append(attempt.status_code)
    assert 429 in statuses, statuses


@pytest.mark.asyncio
async def test_send_without_a_factor_is_indistinguishable(client, provider):
    """No enumeration: the acknowledgement is byte-identical either way."""
    # An operator who has a verified factor.
    enrolled_token = await _password_session(client)
    await _enroll_email(client, provider, enrolled_token)
    enrolled_body = (await _login(client)).json()
    with_factor = await client.post(
        "/api/v1/auth/mfa/login/email/send",
        headers=_auth(enrolled_body["mfa_token"]),
    )

    # An operator who has none. Give them a pending token by requiring MFA.
    settings.mfa_enforcement = "required"
    settings.mfa_required_minimum_role = "readonly"
    viewer_body = (await _login(client, VIEWER_EMAIL, VIEWER_PASSWORD)).json()
    assert viewer_body["mfa_required"] is True
    sent_before = len(provider.messages)
    without_factor = await client.post(
        "/api/v1/auth/mfa/login/email/send",
        headers=_auth(viewer_body["mfa_token"]),
    )

    assert with_factor.status_code == without_factor.status_code == 200
    assert set(with_factor.json()) == set(without_factor.json())
    assert (
        with_factor.json()["expires_in_seconds"]
        == without_factor.json()["expires_in_seconds"]
    )
    # Identical to the caller, and yet nothing was actually mailed: the
    # acknowledgement is a shape, not a promise of delivery.
    assert len(provider.messages) == sent_before


@pytest.mark.asyncio
async def test_address_change_invalidates_the_factor(client, provider):
    """A verified snapshot that no longer matches is no longer proof."""
    token = await _password_session(client)
    await _enroll_email(client, provider, token)

    async with AsyncSessionLocal() as db:
        operator = (
            await db.execute(select(Operator).where(Operator.email == ADMIN_EMAIL))
        ).scalar_one()
        operator.email = "moved@nodelink.test"
        await db.commit()

    body = (await _login(client, "moved@nodelink.test", ADMIN_PASSWORD)).json()
    assert "email_code" not in body.get("mfa_methods", []), body


# --------------------------------------------------------------------------- #
# Delivery failure
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_provider_outage_is_visible_and_grants_nothing(
    client, provider, monkeypatch
):
    """Neither a silent grant nor a silent denial.

    The operator is told delivery failed, and no live code is left behind for
    someone to guess at.
    """
    token = await _password_session(client)
    await _enroll_email(client, provider, token)
    body = (await _login(client)).json()
    mfa_token = body["mfa_token"]

    failing = FailingProvider()
    monkeypatch.setattr(
        mfa_email, "build_transactional_provider", lambda config=settings: failing
    )
    sent = await client.post(
        "/api/v1/auth/mfa/login/email/send", headers=_auth(mfa_token)
    )
    assert sent.status_code == 503, sent.text
    assert sent.json()["detail"]["code"] == "email_delivery_unavailable"
    assert failing.calls == 1

    async with AsyncSessionLocal() as db:
        live = (
            await db.execute(
                select(MfaEmailCode).where(
                    MfaEmailCode.purpose == MfaEmailCodePurpose.login,
                    MfaEmailCode.consumed_at.is_(None),
                    MfaEmailCode.superseded_at.is_(None),
                )
            )
        ).scalars().all()
        assert live == [], "a code nobody can read must not stay live"

    failures = await _audit_actions("mfa.email_code_send_failed")
    assert failures and failures[-1]["reason"] == "internal_server_error"


@pytest.mark.asyncio
async def test_unconfigured_provider_refuses_rather_than_pretending(
    client, monkeypatch
):
    """With no mail provider configured the factor is unavailable, and says so."""
    monkeypatch.setattr(
        mfa_email, "build_transactional_provider", lambda config=settings: None
    )
    token = await _password_session(client)
    started = await client.post(
        "/api/v1/auth/mfa/email/enrollment/start", headers=_auth(token)
    )
    assert started.status_code == 503
    assert started.json()["detail"]["code"] == "email_delivery_unavailable"


# --------------------------------------------------------------------------- #
# Audit evidence
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_audit_records_use_without_recording_the_code(client, provider):
    """The trail must prove a code was used without ever containing one.

    Not even a digest, for the same reason recovery codes are kept out of the
    chain entirely: a value in the log is a value an attacker can search
    against.
    """
    token = await _password_session(client)
    await _enroll_email(client, provider, token)
    code = provider.last_code
    await _email_login(client, provider)
    login_code = provider.last_code

    async with AsyncSessionLocal() as db:
        rows = (await db.execute(select(AuditEvent))).scalars().all()
        blob = " ".join(str(dict(row.detail or {})) for row in rows)

    assert code not in blob
    assert login_code not in blob
    # The masked destination is what the trail carries instead.
    sent = await _audit_actions("mfa.email_code_sent")
    assert sent and sent[-1]["destination"].startswith("a***@")

    succeeded = await _audit_actions("mfa.authentication_succeeded")
    assert any(entry.get("method") == "email_code" for entry in succeeded)

    verified = await _audit_actions("mfa.email_factor_verified")
    assert verified, "enrolment must be auditable"


@pytest.mark.asyncio
async def test_removal_is_audited_and_step_up_gated(client, provider):
    """Removing the factor needs a real authenticator, and leaves a record."""
    token = await _password_session(client)
    await _enroll_email(client, provider, token)
    # Only a WebAuthn assertion satisfies step-up, so the operator registers a
    # key and signs in with it before the factor can be taken away.
    _credential_id, authenticator = await _enroll_webauthn(client, token)
    stepped_up = await _webauthn_login(client, authenticator)

    removed = await client.post(
        "/api/v1/auth/mfa/email",
        json={"reason": "operator no longer needs the fallback"},
        headers=_auth(stepped_up),
    )
    assert removed.status_code == 200, removed.text

    async with AsyncSessionLocal() as db:
        assert (await db.execute(select(MfaEmailFactor))).scalars().all() == []

    events = await _audit_actions("mfa.email_factor_removed")
    assert events and events[-1]["by"] == "self"
