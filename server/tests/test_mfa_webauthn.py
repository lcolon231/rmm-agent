# SPDX-License-Identifier: AGPL-3.0-only
"""WebAuthn MFA, step-up, and audited recovery (issue #67).

Every ceremony in this file is produced by a real software authenticator
(``tests/webauthn_authenticator.py``) signing real bytes with a real key. A
negative test here fails because the cryptography or the state check actually
refuses it, not because a stub was told to return False — which is the only way
these tests are worth anything as evidence for a security control.

The file is organised as: verification-core unit tests, then the login and
enrolment flows, then the negative and abuse cases, then policy/rollout, then
recovery and administrative reset, then audit evidence.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///./test_mfa_webauthn.db")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("COMMAND_SIGNING_KEY_PATH", "command_signing_key.pem")

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.api import deps  # noqa: E402
from app.core import mfa  # noqa: E402
from app.core import webauthn as wa  # noqa: E402
from app.core.cbor import CBORDecodeError, decode  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.database import AsyncSessionLocal, Base, engine  # noqa: E402
from app.core.security import (  # noqa: E402
    AMR_PASSWORD,
    AMR_RECOVERY_CODE,
    AMR_WEBAUTHN,
    create_access_token,
    decode_access_token,
    hash_password,
)
from app.main import app  # noqa: E402
from app.models.models import (  # noqa: E402
    AuditEvent,
    MfaRecoveryCode,
    Operator,
    OperatorRole,
    WebAuthnChallenge,
    WebAuthnChallengePurpose,
    WebAuthnCredential,
)
from tests.webauthn_authenticator import (  # noqa: E402
    COSE_ALG_EDDSA,
    SoftwareAuthenticator,
    b64url,
    cbor_encode,
)

RP_ID = "rmm.test"
ORIGIN = "https://rmm.test"
ORIGINS = frozenset({ORIGIN})

ADMIN_EMAIL = "admin@nodelink.test"
ADMIN_PASSWORD = "correct-horse-battery"
SECOND_ADMIN_EMAIL = "second-admin@nodelink.test"
VIEWER_EMAIL = "viewer@nodelink.test"
VIEWER_PASSWORD = "read-only-pass"


@pytest.fixture(autouse=True)
def mfa_settings():
    """Pin the MFA-relevant settings for the duration of each test.

    Set on the settings object rather than through the environment: the whole
    suite runs in one process and ``settings`` is built at first import, so an
    environment variable set by this module would only take effect when this
    module happened to be imported first. Restoring afterwards keeps the change
    from leaking into files that run later.
    """
    saved = {
        name: getattr(settings, name)
        for name in (
            "public_base_url",
            "mfa_enforcement",
            "mfa_required_minimum_role",
            "mfa_require_user_verification",
            "mfa_max_credentials_per_operator",
            "mfa_step_up_max_age_seconds",
            "mfa_rp_id",
            "mfa_allowed_origins",
        )
    }
    settings.public_base_url = ORIGIN
    settings.mfa_rp_id = None
    settings.mfa_allowed_origins = ""
    settings.mfa_enforcement = "optional"
    settings.mfa_required_minimum_role = "admin"
    settings.mfa_require_user_verification = True
    settings.mfa_max_credentials_per_operator = 10
    settings.mfa_step_up_max_age_seconds = 900
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
        db.add(
            Operator(
                email=ADMIN_EMAIL,
                password_hash=hash_password(ADMIN_PASSWORD),
                role=OperatorRole.admin,
            )
        )
        # A second active admin, so the last-active-admin guard never masks the
        # MFA behaviour these tests are actually about.
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
# Flow helpers
# --------------------------------------------------------------------------- #
def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _login(c, email=ADMIN_EMAIL, password=ADMIN_PASSWORD):
    response = await c.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )
    return response


async def _password_session(c, email=ADMIN_EMAIL, password=ADMIN_PASSWORD) -> str:
    """A full session from a password alone (only valid before enrolment)."""
    body = (await _login(c, email, password)).json()
    assert body["access_token"], body
    return body["access_token"]


def _new_authenticator(**kwargs) -> SoftwareAuthenticator:
    kwargs.setdefault("rp_id", RP_ID)
    kwargs.setdefault("origin", ORIGIN)
    return SoftwareAuthenticator(**kwargs)


async def _enroll(c, token: str, authenticator: SoftwareAuthenticator, name="Test key"):
    """Run a full registration ceremony with `token` as the credential."""
    options = await c.post("/api/v1/auth/mfa/credentials/options", headers=_auth(token))
    if options.status_code != 200:
        # Let the caller assert on a refusal (limit reached, MFA off, ...)
        # rather than hiding it behind an assertion in the helper.
        return options
    challenge = wa.b64url_decode(options.json()["challenge"])
    created = authenticator.register(challenge)
    return await c.post(
        "/api/v1/auth/mfa/credentials",
        headers=_auth(token),
        json={
            "name": name,
            "client_data_json": created["client_data_json"],
            "attestation_object": created["attestation_object"],
            "transports": ["usb"],
        },
    )


async def _assert_ceremony(
    c, token: str, authenticator: SoftwareAuthenticator, *, kind: str, **assert_kwargs
):
    """Run an options+verify assertion round trip for login or step-up."""
    options = await c.post(f"/api/v1/auth/mfa/{kind}/options", headers=_auth(token))
    assert options.status_code == 200, options.text
    challenge = wa.b64url_decode(options.json()["challenge"])
    signed = authenticator.assert_(challenge, **assert_kwargs)
    return await c.post(
        f"/api/v1/auth/mfa/{kind}/verify",
        headers=_auth(token),
        json={
            "credential_id": signed["id"],
            "client_data_json": signed["client_data_json"],
            "authenticator_data": signed["authenticator_data"],
            "signature": signed["signature"],
        },
    )


async def _enrolled_session(c, email=ADMIN_EMAIL, password=ADMIN_PASSWORD):
    """Enrol an authenticator and return (step-up-fresh session, authenticator)."""
    bootstrap = await _password_session(c, email, password)
    authenticator = _new_authenticator()
    assert (await _enroll(c, bootstrap, authenticator)).status_code == 201

    body = (await _login(c, email, password)).json()
    assert body["mfa_required"] is True
    verified = await _assert_ceremony(
        c, body["mfa_token"], authenticator, kind="login"
    )
    assert verified.status_code == 200, verified.text
    return verified.json()["access_token"], authenticator


async def _audit_actions(action: str | None = None) -> list[AuditEvent]:
    async with AsyncSessionLocal() as db:
        query = select(AuditEvent).order_by(AuditEvent.seq)
        if action is not None:
            query = query.where(AuditEvent.action == action)
        return list((await db.execute(query)).scalars().all())


# =========================================================================== #
# Verification core
# =========================================================================== #
def test_relying_party_derives_from_public_base_url():
    party = mfa.relying_party()
    assert party.rp_id == RP_ID
    assert ORIGIN in party.origins


def test_authentication_method_names_are_a_stable_wire_contract():
    """The `amr` values travel in a signed claim and are read by the dashboard.

    Changing one is a breaking change to the session contract, not a rename, so
    the values are pinned here rather than left implicit in the flow tests --
    those assert against these constants so a rename cannot silently pass.
    """
    assert sorted((AMR_PASSWORD, AMR_WEBAUTHN, AMR_RECOVERY_CODE)) == [
        "pwd",  # RFC 8176 method name meaning "a password was used"
        "recovery_code",
        "webauthn",
    ]


def test_role_rank_matches_the_authorization_table():
    # mfa duplicates deps._ROLE_RANK to avoid a circular import. If the two ever
    # drift, MFA policy and role authorization would disagree about privilege.
    assert mfa._ROLE_RANK == deps._ROLE_RANK


@pytest.mark.parametrize("algorithm", [-7, COSE_ALG_EDDSA])
def test_registration_and_assertion_round_trip(algorithm):
    authenticator = _new_authenticator(algorithm=algorithm)
    challenge = wa.generate_challenge()
    created = authenticator.register(challenge)
    registration = wa.verify_registration(
        client_data_json=created["raw_client_data_json"],
        attestation_object=created["raw_attestation_object"],
        expected_challenge=challenge,
        expected_origins=ORIGINS,
        expected_rp_id=RP_ID,
    )
    assert registration.algorithm == algorithm
    assert registration.credential_id == authenticator.credential_id

    login_challenge = wa.generate_challenge()
    signed = authenticator.assert_(login_challenge)
    result = wa.verify_assertion(
        client_data_json=signed["raw_client_data_json"],
        authenticator_data=signed["raw_authenticator_data"],
        signature=signed["raw_signature"],
        expected_challenge=login_challenge,
        expected_origins=ORIGINS,
        expected_rp_id=RP_ID,
        credential_public_key_cose=registration.public_key_cose,
        stored_sign_count=registration.sign_count,
    )
    assert result.user_verified is True


def test_packed_self_attestation_is_verified_and_x5c_is_refused():
    authenticator = _new_authenticator()
    challenge = wa.generate_challenge()
    created = authenticator.register(challenge, attestation_format="packed")
    assert (
        wa.verify_registration(
            client_data_json=created["raw_client_data_json"],
            attestation_object=created["raw_attestation_object"],
            expected_challenge=challenge,
            expected_origins=ORIGINS,
            expected_rp_id=RP_ID,
        ).attestation_format
        == "packed"
    )

    # A chain we have no root for is refused rather than accepted unverified.
    raw = decode(created["raw_attestation_object"])
    raw["attStmt"]["x5c"] = [b"\x30\x00"]
    with pytest.raises(wa.WebAuthnError) as exc:
        wa.verify_registration(
            client_data_json=created["raw_client_data_json"],
            attestation_object=cbor_encode(raw),
            expected_challenge=challenge,
            expected_origins=ORIGINS,
            expected_rp_id=RP_ID,
        )
    assert exc.value.code == "unsupported_attestation_format"


@pytest.mark.parametrize(
    ("kwargs", "expected_code"),
    [
        ({"origin": "https://rmm.test.evil.example"}, "origin_mismatch"),
        ({"rp_id": "evil.example"}, "rp_id_mismatch"),
        ({"corrupt_signature": True}, "invalid_signature"),
        ({"cross_origin": True}, "cross_origin_not_allowed"),
        ({"flags": 0b0000_0001}, "user_verification_required"),
        ({"flags": 0b0000_0100}, "user_presence_required"),
        ({"ceremony_type": "webauthn.create"}, "client_data_type_mismatch"),
        ({"attested": True}, "unexpected_attested_credential_data"),
    ],
)
def test_assertion_rules_each_refuse_with_their_own_code(kwargs, expected_code):
    authenticator = _new_authenticator()
    registration = wa.verify_registration(
        **_registration_inputs(authenticator),
        expected_origins=ORIGINS,
        expected_rp_id=RP_ID,
    )
    challenge = wa.generate_challenge()
    signed = authenticator.assert_(challenge, **kwargs)
    with pytest.raises(wa.WebAuthnError) as exc:
        wa.verify_assertion(
            client_data_json=signed["raw_client_data_json"],
            authenticator_data=signed["raw_authenticator_data"],
            signature=signed["raw_signature"],
            expected_challenge=challenge,
            expected_origins=ORIGINS,
            expected_rp_id=RP_ID,
            credential_public_key_cose=registration.public_key_cose,
            stored_sign_count=0,
        )
    assert exc.value.code == expected_code


def _registration_inputs(authenticator: SoftwareAuthenticator) -> dict:
    challenge = wa.generate_challenge()
    created = authenticator.register(challenge)
    return {
        "client_data_json": created["raw_client_data_json"],
        "attestation_object": created["raw_attestation_object"],
        "expected_challenge": challenge,
    }


def test_signature_counter_regression_is_refused_but_a_zero_counter_is_allowed():
    authenticator = _new_authenticator()
    registration = wa.verify_registration(
        **_registration_inputs(authenticator),
        expected_origins=ORIGINS,
        expected_rp_id=RP_ID,
    )

    def verify(sign_count: int, stored: int):
        challenge = wa.generate_challenge()
        signed = authenticator.assert_(challenge, sign_count=sign_count)
        return wa.verify_assertion(
            client_data_json=signed["raw_client_data_json"],
            authenticator_data=signed["raw_authenticator_data"],
            signature=signed["raw_signature"],
            expected_challenge=challenge,
            expected_origins=ORIGINS,
            expected_rp_id=RP_ID,
            credential_public_key_cose=registration.public_key_cose,
            stored_sign_count=stored,
        )

    assert verify(10, 5).sign_count == 10
    # A cloned authenticator replays an older counter value.
    for cloned in (5, 4):
        with pytest.raises(wa.WebAuthnError) as exc:
            verify(cloned, 5)
        assert exc.value.code == "sign_count_regressed"
    # Authenticators without a counter report 0 forever and must keep working.
    assert verify(0, 5).sign_count == 0


def test_cose_keys_outside_the_supported_set_are_refused():
    # An unregistered algorithm cannot be stored, so it can never reach a
    # verification path that does not know how to check it.
    with pytest.raises(wa.WebAuthnError) as exc:
        wa.load_cose_key(cbor_encode({1: 2, 3: -36, -1: 3, -2: b"x" * 66, -3: b"y" * 66}))
    assert exc.value.code == "unsupported_algorithm"

    # Right algorithm, wrong curve.
    with pytest.raises(wa.WebAuthnError) as exc:
        wa.load_cose_key(cbor_encode({1: 2, 3: -7, -1: 2, -2: b"x" * 32, -3: b"y" * 32}))
    assert exc.value.code == "unsupported_curve"

    # Correctly-shaped P-256 key with a short coordinate: a different encoding
    # than the one the authenticator signed under.
    with pytest.raises(wa.WebAuthnError) as exc:
        wa.load_cose_key(cbor_encode({1: 2, 3: -7, -1: 1, -2: b"x" * 31, -3: b"y" * 32}))
    assert exc.value.code == "malformed_credential_public_key"

    # An undersized RSA modulus is refused rather than stored and trusted.
    with pytest.raises(wa.WebAuthnError) as exc:
        wa.load_cose_key(cbor_encode({1: 3, 3: -257, -1: b"\x01" * 128, -2: b"\x01\x00\x01"}))
    assert exc.value.code == "weak_public_key"


def test_cbor_decoder_rejects_the_shapes_webauthn_forbids():
    # Indefinite-length encodings are forbidden by CTAP2 canonical CBOR and are
    # where length-confusion bugs live.
    with pytest.raises(CBORDecodeError):
        decode(bytes.fromhex("5f42010243040506ff"))
    # Duplicate map keys are a parser-differential primitive.
    with pytest.raises(CBORDecodeError):
        decode(bytes.fromhex("a2010102 0102".replace(" ", "")))
    # Trailing data must not be silently ignored.
    with pytest.raises(CBORDecodeError):
        decode(cbor_encode({1: 1}) + b"extra")
    # Tags carry no meaning in these structures.
    with pytest.raises(CBORDecodeError):
        decode(bytes.fromhex("c11a514b67b0"))


def test_base64url_decoding_rejects_out_of_alphabet_input():
    # Python's lenient decoder would drop these characters, letting two
    # different strings compare equal to one challenge.
    for bad in ("abc!def", "ab cd", "++//"):
        with pytest.raises(wa.WebAuthnError):
            wa.b64url_decode(bad)
    assert wa.b64url_decode(wa.b64url_encode(b"\x00\xff")) == b"\x00\xff"


# =========================================================================== #
# Login and enrolment flows
# =========================================================================== #
@pytest.mark.asyncio
async def test_password_only_login_is_unchanged_when_nobody_is_enrolled(client):
    body = (await _login(client)).json()
    assert body["mfa_required"] is False
    assert body["token_type"] == "bearer"
    # The pre-MFA response shape survives, so an older dashboard build works.
    assert body["access_token"]
    me = await client.get("/api/v1/auth/me", headers=_auth(body["access_token"]))
    assert me.status_code == 200


@pytest.mark.asyncio
async def test_enrolled_operator_must_present_the_second_factor(client):
    bootstrap = await _password_session(client)
    authenticator = _new_authenticator()
    assert (await _enroll(client, bootstrap, authenticator)).status_code == 201

    body = (await _login(client)).json()
    assert body["access_token"] is None
    assert body["mfa_required"] is True
    assert body["mfa_methods"] == ["webauthn"]

    # The restricted token is not a session: it opens nothing.
    for path in ("/api/v1/auth/me", "/api/v1/auth/mfa/status", "/api/v1/auth/operators"):
        blocked = await client.get(path, headers=_auth(body["mfa_token"]))
        assert blocked.status_code == 401, path

    completed = await _assert_ceremony(
        client, body["mfa_token"], authenticator, kind="login"
    )
    assert completed.status_code == 200
    session = completed.json()["access_token"]
    assert (await client.get("/api/v1/auth/me", headers=_auth(session))).status_code == 200

    claims = decode_access_token(session)
    assert set(claims["amr"]) == {AMR_PASSWORD, AMR_WEBAUTHN}
    assert claims["typ"] == "access"
    assert claims["sua"]


@pytest.mark.asyncio
async def test_a_full_session_cannot_replay_the_login_ceremony(client):
    session, _ = await _enrolled_session(client)
    # An already-complete session has no business minting another one.
    replay = await client.post("/api/v1/auth/mfa/login/options", headers=_auth(session))
    assert replay.status_code == 401


@pytest.mark.asyncio
async def test_registered_device_is_listed_with_its_name_and_can_be_renamed(client):
    session, _ = await _enrolled_session(client)
    listed = await client.get("/api/v1/auth/mfa/credentials", headers=_auth(session))
    assert listed.status_code == 200
    [device] = listed.json()
    assert device["name"] == "Test key"
    assert device["transports"] == "usb"
    assert device["last_used_at"] is not None

    renamed = await client.put(
        f"/api/v1/auth/mfa/credentials/{device['id']}",
        headers=_auth(session),
        json={"name": "Front desk YubiKey"},
    )
    assert renamed.status_code == 200
    assert renamed.json()["name"] == "Front desk YubiKey"


@pytest.mark.asyncio
async def test_status_reports_enrolment_and_session_capability(client):
    session, _ = await _enrolled_session(client)
    status_body = (
        await client.get("/api/v1/auth/mfa/status", headers=_auth(session))
    ).json()
    assert status_body["enrolled"] is True
    assert status_body["credential_count"] == 1
    assert status_body["step_up_satisfied"] is True
    assert status_body["session_methods"] == sorted({AMR_PASSWORD, AMR_WEBAUTHN})


# =========================================================================== #
# Negative and abuse cases at the API boundary
# =========================================================================== #
@pytest.mark.asyncio
async def test_a_challenge_is_single_use_so_an_assertion_cannot_be_replayed(client):
    bootstrap = await _password_session(client)
    authenticator = _new_authenticator()
    assert (await _enroll(client, bootstrap, authenticator)).status_code == 201

    body = (await _login(client)).json()
    options = await client.post(
        "/api/v1/auth/mfa/login/options", headers=_auth(body["mfa_token"])
    )
    challenge = wa.b64url_decode(options.json()["challenge"])
    signed = authenticator.assert_(challenge)
    payload = {
        "credential_id": signed["id"],
        "client_data_json": signed["client_data_json"],
        "authenticator_data": signed["authenticator_data"],
        "signature": signed["signature"],
    }

    first = await client.post(
        "/api/v1/auth/mfa/login/verify", headers=_auth(body["mfa_token"]), json=payload
    )
    assert first.status_code == 200

    # Byte-identical replay of a genuinely valid assertion.
    replay = await client.post(
        "/api/v1/auth/mfa/login/verify", headers=_auth(body["mfa_token"]), json=payload
    )
    assert replay.status_code == 401

    async with AsyncSessionLocal() as db:
        rows = list((await db.execute(select(WebAuthnChallenge))).scalars().all())
    assert all(row.consumed_at is not None for row in rows)


@pytest.mark.asyncio
async def test_an_expired_challenge_cannot_be_spent(client):
    bootstrap = await _password_session(client)
    authenticator = _new_authenticator()
    assert (await _enroll(client, bootstrap, authenticator)).status_code == 201
    body = (await _login(client)).json()

    options = await client.post(
        "/api/v1/auth/mfa/login/options", headers=_auth(body["mfa_token"])
    )
    challenge = wa.b64url_decode(options.json()["challenge"])
    async with AsyncSessionLocal() as db:
        row = (
            await db.execute(
                select(WebAuthnChallenge).where(
                    WebAuthnChallenge.purpose
                    == WebAuthnChallengePurpose.authentication
                )
            )
        ).scalars().one()
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await db.commit()

    signed = authenticator.assert_(challenge)
    late = await client.post(
        "/api/v1/auth/mfa/login/verify",
        headers=_auth(body["mfa_token"]),
        json={
            "credential_id": signed["id"],
            "client_data_json": signed["client_data_json"],
            "authenticator_data": signed["authenticator_data"],
            "signature": signed["signature"],
        },
    )
    assert late.status_code == 401


@pytest.mark.parametrize(
    "kwargs",
    [
        {"origin": "https://rmm.test.evil.example"},
        {"rp_id": "evil.example"},
        {"corrupt_signature": True},
        {"flags": 0b0000_0001},
    ],
)
@pytest.mark.asyncio
async def test_refused_ceremonies_return_one_generic_error(client, kwargs):
    bootstrap = await _password_session(client)
    authenticator = _new_authenticator()
    assert (await _enroll(client, bootstrap, authenticator)).status_code == 201
    body = (await _login(client)).json()

    refused = await _assert_ceremony(
        client, body["mfa_token"], authenticator, kind="login", **kwargs
    )
    assert refused.status_code == 401
    # One message for every rule, so a caller learns nothing about which failed.
    assert refused.json()["detail"] == "Multi-factor authentication failed"
    # The coded reason is preserved where it belongs: the audit chain.
    assert [event.action for event in await _audit_actions("mfa.authentication_failed")]


@pytest.mark.asyncio
async def test_one_operator_cannot_authenticate_with_another_operators_credential(
    client,
):
    admin_session, admin_authenticator = await _enrolled_session(client)

    # The viewer knows their own password and steals the admin's credential ID.
    viewer_login = (await _login(client, VIEWER_EMAIL, VIEWER_PASSWORD)).json()
    assert viewer_login["access_token"], "viewer is not enrolled, so no MFA applies"

    # Enrol the viewer, then try to complete their login with the admin's key.
    viewer_authenticator = _new_authenticator()
    assert (
        await _enroll(client, viewer_login["access_token"], viewer_authenticator)
    ).status_code == 201
    body = (await _login(client, VIEWER_EMAIL, VIEWER_PASSWORD)).json()

    options = await client.post(
        "/api/v1/auth/mfa/login/options", headers=_auth(body["mfa_token"])
    )
    challenge = wa.b64url_decode(options.json()["challenge"])
    signed = admin_authenticator.assert_(challenge)
    stolen = await client.post(
        "/api/v1/auth/mfa/login/verify",
        headers=_auth(body["mfa_token"]),
        json={
            "credential_id": signed["id"],
            "client_data_json": signed["client_data_json"],
            "authenticator_data": signed["authenticator_data"],
            "signature": signed["signature"],
        },
    )
    assert stolen.status_code == 401
    assert admin_session  # the admin's own session is untouched


@pytest.mark.asyncio
async def test_the_same_authenticator_cannot_be_bound_to_two_identities(client):
    admin_session, authenticator = await _enrolled_session(client)
    viewer_session = await _password_session(client, VIEWER_EMAIL, VIEWER_PASSWORD)
    conflict = await _enroll(client, viewer_session, authenticator)
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["code"] == "credential_already_registered"
    assert admin_session


@pytest.mark.asyncio
async def test_a_disabled_operator_cannot_complete_a_login(client):
    bootstrap = await _password_session(client)
    authenticator = _new_authenticator()
    assert (await _enroll(client, bootstrap, authenticator)).status_code == 201
    body = (await _login(client)).json()

    async with AsyncSessionLocal() as db:
        operator = (
            await db.execute(select(Operator).where(Operator.email == ADMIN_EMAIL))
        ).scalars().one()
        operator.disabled = True
        await db.commit()

    # The restricted token stops working the moment the account does — the
    # half-finished login is not a way around a disabled account.
    blocked = await client.post(
        "/api/v1/auth/mfa/login/options", headers=_auth(body["mfa_token"])
    )
    assert blocked.status_code == 401


@pytest.mark.asyncio
async def test_revoking_sessions_invalidates_an_outstanding_mfa_token(client):
    bootstrap = await _password_session(client)
    authenticator = _new_authenticator()
    assert (await _enroll(client, bootstrap, authenticator)).status_code == 201
    body = (await _login(client)).json()

    async with AsyncSessionLocal() as db:
        operator = (
            await db.execute(select(Operator).where(Operator.email == ADMIN_EMAIL))
        ).scalars().one()
        operator.token_generation += 1
        await db.commit()

    stale = await client.post(
        "/api/v1/auth/mfa/login/options", headers=_auth(body["mfa_token"])
    )
    assert stale.status_code == 401


@pytest.mark.asyncio
async def test_failed_second_factor_attempts_are_rate_limited(client):
    bootstrap = await _password_session(client)
    authenticator = _new_authenticator()
    assert (await _enroll(client, bootstrap, authenticator)).status_code == 201
    body = (await _login(client)).json()

    for _ in range(settings.mfa_max_failures):
        refused = await _assert_ceremony(
            client,
            body["mfa_token"],
            authenticator,
            kind="login",
            corrupt_signature=True,
        )
        assert refused.status_code == 401

    limited = await _assert_ceremony(
        client, body["mfa_token"], authenticator, kind="login", corrupt_signature=True
    )
    assert limited.status_code == 429
    assert limited.headers["Retry-After"]


@pytest.mark.asyncio
async def test_enrolment_is_bounded_per_operator(client):
    settings.mfa_max_credentials_per_operator = 2
    session, authenticator = await _enrolled_session(client)
    assert (await _enroll(client, session, _new_authenticator(), "second")).status_code == 201
    refused = await _enroll(client, session, _new_authenticator(), "third")
    assert refused.status_code == 409
    assert refused.json()["detail"]["code"] == "credential_limit_reached"


@pytest.mark.asyncio
async def test_a_password_only_session_cannot_plant_another_authenticator(client):
    """A stolen session must not be able to quietly add its own device."""
    session, _ = await _enrolled_session(client)
    # Forge a password-only session for the same operator, as a stolen cookie
    # from before enrolment would be.
    async with AsyncSessionLocal() as db:
        operator = (
            await db.execute(select(Operator).where(Operator.email == ADMIN_EMAIL))
        ).scalars().one()
        password_only = create_access_token(
            subject=operator.id, generation=operator.token_generation
        )

    refused = await client.post(
        "/api/v1/auth/mfa/credentials/options", headers=_auth(password_only)
    )
    assert refused.status_code == 403
    assert refused.json()["detail"]["code"] == "mfa_verification_required"
    assert session


# =========================================================================== #
# Step-up
# =========================================================================== #
@pytest.mark.asyncio
async def test_step_up_gated_operations_refuse_a_stale_session(client):
    session, authenticator = await _enrolled_session(client)
    [device] = (
        await client.get("/api/v1/auth/mfa/credentials", headers=_auth(session))
    ).json()

    # Age the session past the step-up window.
    settings.mfa_step_up_max_age_seconds = 0
    stale = await client.post(
        f"/api/v1/auth/mfa/credentials/{device['id']}/revoke",
        headers=_auth(session),
        json={"reason": "Retiring this key"},
    )
    assert stale.status_code == 403
    assert stale.json()["detail"]["code"] == "step_up_required"

    settings.mfa_step_up_max_age_seconds = 900
    refreshed = await _assert_ceremony(client, session, authenticator, kind="step-up")
    assert refreshed.status_code == 200
    stepped_up = refreshed.json()["access_token"]
    assert decode_access_token(stepped_up)["sua"]


@pytest.mark.asyncio
async def test_admin_operator_management_requires_step_up_once_enrolled(client):
    session, authenticator = await _enrolled_session(client)
    viewer_id = await _operator_id(VIEWER_EMAIL)

    settings.mfa_step_up_max_age_seconds = 0
    for request in (
        client.put(
            f"/api/v1/auth/operators/{viewer_id}/role",
            headers=_auth(session),
            json={"role": "operator", "reason": "Promotion"},
        ),
        client.put(
            f"/api/v1/auth/operators/{viewer_id}/disabled",
            headers=_auth(session),
            json={"disabled": True, "reason": "Offboarding"},
        ),
        client.post(
            f"/api/v1/auth/operators/{viewer_id}/revoke-tokens", headers=_auth(session)
        ),
    ):
        response = await request
        assert response.status_code == 403
        assert response.json()["detail"]["code"] == "step_up_required"

    # With a fresh assertion the same calls go through.
    settings.mfa_step_up_max_age_seconds = 900
    fresh = (
        await _assert_ceremony(client, session, authenticator, kind="step-up")
    ).json()["access_token"]
    promoted = await client.put(
        f"/api/v1/auth/operators/{viewer_id}/role",
        headers=_auth(fresh),
        json={"role": "operator", "reason": "Promotion"},
    )
    assert promoted.status_code == 200


@pytest.mark.asyncio
async def test_step_up_is_vacuous_for_operators_with_no_authenticator(client):
    """The compatibility contract: a pre-MFA deployment behaves as it always did."""
    session = await _password_session(client)
    viewer_id = await _operator_id(VIEWER_EMAIL)
    promoted = await client.put(
        f"/api/v1/auth/operators/{viewer_id}/role",
        headers=_auth(session),
        json={"role": "operator", "reason": "Promotion"},
    )
    assert promoted.status_code == 200


async def _operator_id(email: str) -> str:
    async with AsyncSessionLocal() as db:
        operator = (
            await db.execute(select(Operator).where(Operator.email == email))
        ).scalars().one()
        return operator.id


# =========================================================================== #
# Policy and staged rollout
# =========================================================================== #
@pytest.mark.asyncio
async def test_enforcement_off_is_a_true_rollback_position(client):
    session, _ = await _enrolled_session(client)
    settings.mfa_enforcement = "off"

    # An enrolled operator logs in with a password alone again...
    body = (await _login(client)).json()
    assert body["mfa_required"] is False
    assert body["access_token"]
    # ...and no ceremony can be started, so the feature cannot half-re-enable
    # itself through a stale browser tab.
    refused = await client.post(
        "/api/v1/auth/mfa/credentials/options", headers=_auth(body["access_token"])
    )
    assert refused.status_code == 503
    assert refused.json()["detail"]["code"] == "mfa_disabled"
    assert session


@pytest.mark.asyncio
async def test_required_mode_restricts_an_unenrolled_operator_to_enrolment(client):
    settings.mfa_enforcement = "required"
    settings.mfa_required_minimum_role = "admin"

    body = (await _login(client)).json()
    assert body["mfa_required"] is True
    assert body["mfa_enrollment_required"] is True
    assert body["mfa_methods"] == ["enrollment"]
    assert body["access_token"] is None

    # The restricted token reaches enrolment and nothing else.
    assert (
        await client.get("/api/v1/auth/me", headers=_auth(body["mfa_token"]))
    ).status_code == 401
    authenticator = _new_authenticator()
    assert (await _enroll(client, body["mfa_token"], authenticator)).status_code == 201

    # Having complied, the operator now logs in normally with their factor.
    second = (await _login(client)).json()
    assert second["mfa_methods"] == ["webauthn"]
    completed = await _assert_ceremony(
        client, second["mfa_token"], authenticator, kind="login"
    )
    assert completed.status_code == 200


@pytest.mark.asyncio
async def test_required_mode_only_binds_roles_at_or_above_the_floor(client):
    settings.mfa_enforcement = "required"
    settings.mfa_required_minimum_role = "admin"
    # A read-only operator is below the floor and is unaffected.
    body = (await _login(client, VIEWER_EMAIL, VIEWER_PASSWORD)).json()
    assert body["mfa_required"] is False
    assert body["access_token"]


@pytest.mark.asyncio
async def test_an_enrolled_operator_cannot_be_exempted_by_configuration(client):
    """Policy can widen who must enrol; it can never excuse an enrolled operator."""
    session, _ = await _enrolled_session(client)
    settings.mfa_enforcement = "optional"
    settings.mfa_required_minimum_role = "admin"
    body = (await _login(client)).json()
    assert body["mfa_required"] is True
    assert session


@pytest.mark.asyncio
async def test_an_unreadable_enforcement_value_fails_closed(client):
    settings.mfa_enforcement = "disabled-by-typo"
    # Not "off": a typo must not silently disable the control.
    assert mfa.enforcement_mode() == "optional"
    session, _ = await _enrolled_session(client)
    assert (await _login(client)).json()["mfa_required"] is True
    assert session


@pytest.mark.asyncio
async def test_the_last_required_credential_cannot_be_revoked(client):
    # Enrol under the staging position, then tighten the policy — the rollout
    # order a real deployment follows.
    session, authenticator = await _enrolled_session(client)
    settings.mfa_enforcement = "required"
    [device] = (
        await client.get("/api/v1/auth/mfa/credentials", headers=_auth(session))
    ).json()
    refused = await client.post(
        f"/api/v1/auth/mfa/credentials/{device['id']}/revoke",
        headers=_auth(session),
        json={"reason": "Retiring my only key"},
    )
    assert refused.status_code == 409
    assert refused.json()["detail"]["code"] == "last_mfa_credential_required"

    # With a replacement registered, the original can go.
    assert (await _enroll(client, session, _new_authenticator(), "backup")).status_code == 201
    allowed = await client.post(
        f"/api/v1/auth/mfa/credentials/{device['id']}/revoke",
        headers=_auth(session),
        json={"reason": "Retiring the original key"},
    )
    assert allowed.status_code == 200
    assert authenticator


# =========================================================================== #
# Recovery
# =========================================================================== #
@pytest.mark.asyncio
async def test_recovery_codes_are_issued_once_and_each_works_exactly_once(client):
    session, authenticator = await _enrolled_session(client)
    generated = await client.post(
        "/api/v1/auth/mfa/recovery-codes", headers=_auth(session)
    )
    assert generated.status_code == 200
    codes = generated.json()["codes"]
    assert len(codes) == settings.mfa_recovery_code_count
    assert len(set(codes)) == len(codes)

    # Stored only as hashes: the database never holds a usable code.
    async with AsyncSessionLocal() as db:
        rows = list((await db.execute(select(MfaRecoveryCode))).scalars().all())
    assert len(rows) == len(codes)
    assert all(row.code_hash.startswith("$2") for row in rows)
    assert not any(code in row.code_hash for code in codes for row in rows)

    body = (await _login(client)).json()
    assert "recovery_code" in body["mfa_methods"]
    used = await client.post(
        "/api/v1/auth/mfa/login/recovery-code",
        headers=_auth(body["mfa_token"]),
        json={"code": codes[0].lower()},  # humans retype these; case is forgiven
    )
    assert used.status_code == 200

    # The same code is now spent.
    again = (await _login(client)).json()
    replay = await client.post(
        "/api/v1/auth/mfa/login/recovery-code",
        headers=_auth(again["mfa_token"]),
        json={"code": codes[0]},
    )
    assert replay.status_code == 401
    assert authenticator


@pytest.mark.asyncio
async def test_a_recovery_session_can_enrol_a_replacement_but_cannot_step_up(client):
    """Device loss, end to end: recovery gets you back in, then you re-enrol."""
    session, _ = await _enrolled_session(client)
    codes = (
        await client.post("/api/v1/auth/mfa/recovery-codes", headers=_auth(session))
    ).json()["codes"]
    [device] = (
        await client.get("/api/v1/auth/mfa/credentials", headers=_auth(session))
    ).json()

    body = (await _login(client)).json()
    recovered = await client.post(
        "/api/v1/auth/mfa/login/recovery-code",
        headers=_auth(body["mfa_token"]),
        json={"code": codes[0]},
    )
    recovery_session = recovered.json()["access_token"]
    assert set(decode_access_token(recovery_session)["amr"]) == {
        AMR_PASSWORD,
        AMR_RECOVERY_CODE,
    }
    assert "sua" not in decode_access_token(recovery_session)

    # It is a real session for ordinary work...
    assert (
        await client.get("/api/v1/auth/me", headers=_auth(recovery_session))
    ).status_code == 200
    # ...and it can enrol the replacement authenticator, which is the point.
    replacement = _new_authenticator()
    assert (
        await _enroll(client, recovery_session, replacement, "replacement key")
    ).status_code == 201

    # But it never satisfies step-up, so paper alone cannot reconfigure security.
    for refused in (
        await client.post(
            f"/api/v1/auth/mfa/credentials/{device['id']}/revoke",
            headers=_auth(recovery_session),
            json={"reason": "Lost the original device"},
        ),
        await client.post(
            "/api/v1/auth/mfa/recovery-codes", headers=_auth(recovery_session)
        ),
    ):
        assert refused.status_code == 403
        assert refused.json()["detail"]["code"] == "step_up_required"

    # Asserting the replacement key does confer step-up, completing the recovery.
    fresh = (
        await _assert_ceremony(client, recovery_session, replacement, kind="step-up")
    ).json()["access_token"]
    revoked = await client.post(
        f"/api/v1/auth/mfa/credentials/{device['id']}/revoke",
        headers=_auth(fresh),
        json={"reason": "Lost the original device"},
    )
    assert revoked.status_code == 200


@pytest.mark.asyncio
async def test_regenerating_recovery_codes_destroys_the_previous_batch(client):
    session, _ = await _enrolled_session(client)
    first = (
        await client.post("/api/v1/auth/mfa/recovery-codes", headers=_auth(session))
    ).json()["codes"]
    second = (
        await client.post("/api/v1/auth/mfa/recovery-codes", headers=_auth(session))
    ).json()["codes"]
    assert not set(first) & set(second)

    body = (await _login(client)).json()
    stale = await client.post(
        "/api/v1/auth/mfa/login/recovery-code",
        headers=_auth(body["mfa_token"]),
        json={"code": first[0]},
    )
    assert stale.status_code == 401


@pytest.mark.asyncio
async def test_recovery_codes_require_an_authenticator_to_recover_from(client):
    session = await _password_session(client)
    refused = await client.post(
        "/api/v1/auth/mfa/recovery-codes", headers=_auth(session)
    )
    assert refused.status_code == 409
    assert refused.json()["detail"]["code"] == "enrollment_required"


@pytest.mark.asyncio
async def test_admin_reset_clears_every_factor_and_revokes_sessions(client):
    # The target loses their devices entirely.
    victim_session, _ = await _enrolled_session(client, VIEWER_EMAIL, VIEWER_PASSWORD)
    await client.post("/api/v1/auth/mfa/recovery-codes", headers=_auth(victim_session))
    victim_id = await _operator_id(VIEWER_EMAIL)

    admin_session, admin_authenticator = await _enrolled_session(client)
    reset = await client.post(
        f"/api/v1/auth/operators/{victim_id}/mfa/reset",
        headers=_auth(admin_session),
        json={"reason": "Laptop and security key lost in transit"},
    )
    assert reset.status_code == 200
    assert reset.json()["credentials_revoked"] == 1
    assert reset.json()["recovery_codes_invalidated"] == settings.mfa_recovery_code_count

    # The target's old session is gone and their login is password-only again.
    assert (
        await client.get("/api/v1/auth/me", headers=_auth(victim_session))
    ).status_code == 401
    body = (await _login(client, VIEWER_EMAIL, VIEWER_PASSWORD)).json()
    assert body["mfa_required"] is False
    assert body["access_token"]

    async with AsyncSessionLocal() as db:
        credentials = list(
            (
                await db.execute(
                    select(WebAuthnCredential).where(
                        WebAuthnCredential.operator_id == victim_id
                    )
                )
            ).scalars().all()
        )
        codes = list(
            (
                await db.execute(
                    select(MfaRecoveryCode).where(
                        MfaRecoveryCode.operator_id == victim_id
                    )
                )
            ).scalars().all()
        )
    # Tombstoned, not deleted, so the audit trail still points at a real row.
    assert credentials and all(row.revoked_at is not None for row in credentials)
    assert all(row.revoked_reason == "admin_reset" for row in credentials)
    assert codes == []
    assert admin_authenticator


@pytest.mark.asyncio
async def test_admin_reset_requires_admin_role_and_step_up(client):
    victim_id = await _operator_id(VIEWER_EMAIL)
    viewer_session = await _password_session(client, VIEWER_EMAIL, VIEWER_PASSWORD)
    forbidden = await client.post(
        f"/api/v1/auth/operators/{victim_id}/mfa/reset",
        headers=_auth(viewer_session),
        json={"reason": "Trying to reset someone else"},
    )
    assert forbidden.status_code == 403

    admin_session, _ = await _enrolled_session(client)
    settings.mfa_step_up_max_age_seconds = 0
    stale = await client.post(
        f"/api/v1/auth/operators/{victim_id}/mfa/reset",
        headers=_auth(admin_session),
        json={"reason": "Device loss"},
    )
    assert stale.status_code == 403
    assert stale.json()["detail"]["code"] == "step_up_required"


# =========================================================================== #
# Audit evidence
# =========================================================================== #
@pytest.mark.asyncio
async def test_the_ceremony_lifecycle_is_auditable_without_recording_secrets(client):
    session, authenticator = await _enrolled_session(client)
    codes = (
        await client.post("/api/v1/auth/mfa/recovery-codes", headers=_auth(session))
    ).json()["codes"]
    body = (await _login(client)).json()
    await client.post(
        "/api/v1/auth/mfa/login/recovery-code",
        headers=_auth(body["mfa_token"]),
        json={"code": codes[0]},
    )

    events = await _audit_actions()
    actions = [event.action for event in events]
    for expected in (
        "mfa.credential_registered",
        "mfa.second_factor_required",
        "mfa.authentication_succeeded",
        "mfa.recovery_codes_generated",
        "mfa.recovery_code_used",
    ):
        assert expected in actions, actions

    blob = "".join(str(event.detail) for event in events)
    # No recovery code, credential ID, or public key ever reaches the chain.
    for code in codes:
        assert code not in blob
    assert b64url(authenticator.credential_id) not in blob
    # The device name is digested, never stored verbatim.
    registered = next(
        event for event in events if event.action == "mfa.credential_registered"
    )
    assert "name" not in registered.detail
    assert registered.detail["name_sha256"]
    assert "Test key" not in blob


@pytest.mark.asyncio
async def test_an_administrative_reset_names_who_did_it_to_whom(client):
    victim_session, _ = await _enrolled_session(client, VIEWER_EMAIL, VIEWER_PASSWORD)
    victim_id = await _operator_id(VIEWER_EMAIL)
    admin_session, _ = await _enrolled_session(client)
    await client.post(
        f"/api/v1/auth/operators/{victim_id}/mfa/reset",
        headers=_auth(admin_session),
        json={"reason": "Laptop lost in transit"},
    )

    [event] = await _audit_actions("mfa.reset")
    assert event.actor == ADMIN_EMAIL
    assert event.detail["operator_id"] == victim_id
    assert event.detail["by"] == "admin"
    assert event.detail["credentials_revoked"] == 1
    # The free-text justification is digested, not stored.
    assert "Laptop lost in transit" not in str(event.detail)
    assert event.detail["reason_sha256"]
    assert victim_session
