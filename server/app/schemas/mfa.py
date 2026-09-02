# SPDX-License-Identifier: AGPL-3.0-only
"""Request and response contracts for WebAuthn MFA (issue #67).

Two shaping decisions run through this file.

**Binary values cross the wire as unpadded base64url strings**, because that is
the encoding the WebAuthn JSON serialisation uses and the one a browser can hand
back with no re-encoding step of its own. Every such field is validated for
length here so an oversized blob is refused by the request layer, before any
parser sees it.

**Options responses use WebAuthn's own camelCase field names** (``pubKeyCredParams``,
``allowCredentials``, ``rpId``) rather than the snake_case used elsewhere in this
API. They are consumed by ``navigator.credentials`` almost verbatim, and
translating them twice is exactly where a subtle field-name bug would hide.
"""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator

# Bounds on the base64url blobs a ceremony carries. Each is comfortably above a
# real authenticator's output and far below anything worth buffering.
_MAX_CREDENTIAL_ID_CHARS = 1400
_MAX_CLIENT_DATA_CHARS = 8 * 1024
_MAX_ATTESTATION_CHARS = 32 * 1024
_MAX_AUTH_DATA_CHARS = 8 * 1024
_MAX_SIGNATURE_CHARS = 2 * 1024

Base64UrlCredentialId = Annotated[
    str, StringConstraints(min_length=1, max_length=_MAX_CREDENTIAL_ID_CHARS)
]
DeviceName = Annotated[
    str, StringConstraints(min_length=1, max_length=64, strip_whitespace=True)
]
Reason = Annotated[
    str, StringConstraints(min_length=3, max_length=500, strip_whitespace=True)
]


# --------------------------------------------------------------------------- #
# Login
# --------------------------------------------------------------------------- #
class LoginResponse(BaseModel):
    """The result of presenting a correct password.

    Exactly one of two states is described. When no second factor applies,
    ``access_token`` is set and the body is byte-compatible with the
    pre-MFA response, so an older dashboard build keeps working unchanged.
    When a second factor is required, ``access_token`` is null and ``mfa_token``
    carries the restricted token that only the completion endpoints accept.
    """

    access_token: str | None = None
    token_type: str = "bearer"
    mfa_required: bool = False
    #: Short-lived, restricted token. Never a usable session on its own.
    mfa_token: str | None = None
    #: The operator must register an authenticator before doing anything else.
    mfa_enrollment_required: bool = False
    #: Which completion methods this operator may use: "webauthn",
    #: "recovery_code", or "enrollment".
    mfa_methods: list[str] = []


# --------------------------------------------------------------------------- #
# Ceremony options (server -> browser)
# --------------------------------------------------------------------------- #
class PublicKeyCredentialDescriptor(BaseModel):
    type: str = "public-key"
    id: str
    transports: list[str] | None = None


class RegistrationOptionsOut(BaseModel):
    """``PublicKeyCredentialCreationOptions``, base64url-encoded."""

    rp: dict[str, str]
    user: dict[str, str]
    challenge: str
    pubKeyCredParams: list[dict[str, Any]]
    timeout: int
    #: Credentials the operator has already registered. The authenticator uses
    #: this to refuse to enrol itself twice, which keeps the device list honest.
    excludeCredentials: list[PublicKeyCredentialDescriptor]
    authenticatorSelection: dict[str, Any]
    attestation: str = "none"


class AuthenticationOptionsOut(BaseModel):
    """``PublicKeyCredentialRequestOptions``, base64url-encoded."""

    challenge: str
    rpId: str
    timeout: int
    allowCredentials: list[PublicKeyCredentialDescriptor]
    userVerification: str


# --------------------------------------------------------------------------- #
# Ceremony responses (browser -> server)
# --------------------------------------------------------------------------- #
class RegistrationVerification(BaseModel):
    """A ``navigator.credentials.create()`` result plus the device's label.

    The credential ID is deliberately *not* accepted from the client: it is
    parsed out of the signed attestation object instead, so a caller cannot
    register one credential under another one's identifier.
    """

    name: DeviceName
    client_data_json: Annotated[
        str, StringConstraints(min_length=1, max_length=_MAX_CLIENT_DATA_CHARS)
    ]
    attestation_object: Annotated[
        str, StringConstraints(min_length=1, max_length=_MAX_ATTESTATION_CHARS)
    ]
    transports: list[Annotated[str, StringConstraints(max_length=16)]] | None = None

    @field_validator("transports")
    @classmethod
    def bound_transports(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        # Hints only — they steer the browser's UI and never a trust decision,
        # so they are bounded and otherwise passed through unexamined.
        return value[:8]


class AssertionVerification(BaseModel):
    """A ``navigator.credentials.get()`` result."""

    credential_id: Base64UrlCredentialId
    client_data_json: Annotated[
        str, StringConstraints(min_length=1, max_length=_MAX_CLIENT_DATA_CHARS)
    ]
    authenticator_data: Annotated[
        str, StringConstraints(min_length=1, max_length=_MAX_AUTH_DATA_CHARS)
    ]
    signature: Annotated[
        str, StringConstraints(min_length=1, max_length=_MAX_SIGNATURE_CHARS)
    ]


class RecoveryCodeVerification(BaseModel):
    code: Annotated[str, StringConstraints(min_length=1, max_length=64)]


class EmailCodeVerification(BaseModel):
    """One presented email one-time code (issue #226).

    Bounded generously rather than to the exact code length: the server
    normalises away spaces and separators a mail client may have introduced, and
    refusing a correctly-typed code because it arrived with a stray space would
    push operators towards the request-another-code loop the send limiter exists
    to prevent.
    """

    code: Annotated[str, StringConstraints(min_length=1, max_length=32)]


class EmailCodeSent(BaseModel):
    """The acknowledgement of a send request.

    Deliberately identical whether or not the operator actually has an email
    factor: the destination is always the operator's own login address, so
    echoing it back masked discloses nothing that the caller -- who already
    presented the correct password -- does not know. Nothing here says whether a
    message was really put on the wire.
    """

    #: Masked form of the operator's login address, for the "we sent a code
    #: to ..." line in the UI.
    destination: str
    expires_in_seconds: int


class EmailFactorOut(BaseModel):
    """The operator's email factor as the dashboard should render it."""

    #: False while an enrolment is in progress. Only a verified factor counts.
    verified: bool
    #: Masked. The full address is the operator's own login email, which the
    #: dashboard already knows; masking keeps it out of one more response body.
    destination: str | None = None
    verified_at: datetime | None = None


class CredentialRename(BaseModel):
    name: DeviceName


class CredentialRevoke(BaseModel):
    reason: Reason


class MfaReset(BaseModel):
    reason: Reason


# --------------------------------------------------------------------------- #
# Views
# --------------------------------------------------------------------------- #
class WebAuthnCredentialOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    algorithm: int
    aaguid: str
    transports: str | None
    attestation_format: str
    backup_eligible: bool
    backup_state: bool
    created_at: datetime
    last_used_at: datetime | None


class MfaStatusOut(BaseModel):
    """Everything the dashboard needs to render the operator's MFA state."""

    enforcement: str
    #: Whether policy obliges this operator to hold a second factor.
    enrollment_required: bool
    enrolled: bool
    credential_count: int
    recovery_codes_remaining: int
    #: Whether the *current session* could perform a step-up-gated operation
    #: right now. Lets the dashboard prompt before an action rather than after
    #: a 403.
    step_up_satisfied: bool
    session_methods: list[str]
    credentials: list[WebAuthnCredentialOut]
    #: Configured position for the email factor: "off", "fallback_only", or
    #: "always" (issue #226). The dashboard needs it to explain *why* the email
    #: option is or is not offered, rather than silently hiding it.
    email_code_policy: str = "off"
    #: The operator's email factor, or null if they have none.
    email_factor: EmailFactorOut | None = None


class RecoveryCodesOut(BaseModel):
    """The one and only time these codes exist outside the operator's hands."""

    codes: list[str]
    generated_at: datetime


class MfaResetOut(BaseModel):
    operator_id: str
    credentials_revoked: int
    recovery_codes_invalidated: int
